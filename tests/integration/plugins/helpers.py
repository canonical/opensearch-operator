#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions related to testing the different plugins."""
import json
import logging
import random
from typing import Any, Dict, List, Optional, Tuple

from pytest_operator.plugin import OpsTest
from tenacity import (
    RetryError,
    Retrying,
    retry,
    stop_after_attempt,
    wait_fixed,
    wait_random,
)

from tests.integration.ha.helpers_data import bulk_insert, create_index
from tests.integration.helpers import get_application_unit_ids, http_request

logger = logging.getLogger(__name__)


async def service_start_time(ops_test: OpsTest, app: str, unit_id: int) -> float:
    """Get the start date unix timestamp of the opensearch service."""
    unit_name = f"{app}/{unit_id}"

    boot_time_cmd = f"ssh {unit_name} awk '/btime/ {{print $2}}' /proc/stat"
    _, unit_boot_time, _ = await ops_test.juju(*boot_time_cmd.split(), check=True)
    unit_boot_time = int(unit_boot_time.rstrip())

    active_since_cmd = f"exec --unit {unit_name} -- systemctl show snap.opensearch.daemon --property=ActiveEnterTimestampMonotonic --value"
    _, active_time_since_boot, _ = await ops_test.juju(*active_since_cmd.split(), check=True)
    active_time_since_boot = int(active_time_since_boot.rstrip()) / 1000000

    return unit_boot_time + active_time_since_boot


async def get_application_unit_ids_start_time(ops_test: OpsTest, app: str) -> Dict[int, float]:
    """Get opensearch start time by unit."""
    result = {}

    for u_id in get_application_unit_ids(ops_test, app):
        result[u_id] = await service_start_time(ops_test, app, u_id)
    return result


async def is_each_unit_restarted(
    ops_test: OpsTest, app: str, previous_timestamps: Dict[int, float]
) -> bool:
    """Check if all units are restarted."""
    try:
        for attempt in Retrying(stop=stop_after_attempt(15), wait=wait_fixed(wait=5)):
            with attempt:
                for u_id, new_timestamp in (
                    await get_application_unit_ids_start_time(ops_test, app)
                ).items():
                    if new_timestamp <= previous_timestamps[u_id]:
                        raise Exception
                return True
    except RetryError:
        return False


def generate_bulk_training_data(
    index_name: str,
    vector_name: str,
    docs_count: int = 100,
    dimensions: int = 4,
    has_result: bool = False,
) -> Tuple[str, List[str]]:
    random.seed("seed")
    print("The seed for randomness is: 'seed'")

    data = random.randbytes(docs_count * dimensions)
    if has_result:
        responses = random.randbytes(docs_count)
    result = ""
    result_list = []
    for i in range(docs_count):
        result += json.dumps({"index": {"_index": index_name, "_id": i}}) + "\n"
        result_list.append([float(data[j]) for j in range(i * dimensions, (i + 1) * dimensions)])
        inter = {vector_name: result_list[i]}
        if has_result:
            inter["price"] = float(responses[i])
        result += json.dumps(inter) + "\n"
    return result, result_list


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def run_knn_training(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    model_name: str,
    payload: Dict[str, Any],
) -> Optional[List[Dict[str, Any]]]:
    """Sets models."""
    endpoint = f"https://{unit_ip}:9200/_plugins/_knn/models/{model_name}/_train"
    return await http_request(ops_test, "POST", endpoint, payload=payload, app=app)


async def is_knn_training_complete(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    model_name: str,
) -> bool:
    """Waits training models."""
    endpoint = f"https://{unit_ip}:9200/_plugins/_knn/models/{model_name}"
    try:
        for attempt in Retrying(stop=stop_after_attempt(15), wait=wait_fixed(wait=5)):
            with attempt:
                resp = await http_request(ops_test, "GET", endpoint, app=app)
                if "created" not in resp.get("state", ""):
                    raise Exception
                return True
    except RetryError:
        return False


async def create_index_and_bulk_insert(
    ops_test: OpsTest,
    app: str,
    endpoint: str,
    index_name: str,
    shards: int,
    vector_name: str,
    model_name: str = None,
) -> List[float]:
    if model_name:
        extra_mappings = {
            "properties": {
                vector_name: {
                    "type": "knn_vector",
                    "model_id": model_name,
                }
            }
        }
        extra_settings = {"index.knn": "true"}
    else:
        extra_mappings = {
            "properties": {
                vector_name: {
                    "type": "knn_vector",
                    "dimension": 4,
                }
            }
        }
        extra_settings = {}

    await create_index(
        ops_test,
        app,
        endpoint,
        index_name,
        r_shards=shards,
        extra_index_settings=extra_settings,
        extra_mappings=extra_mappings,
    )
    payload, payload_list = generate_bulk_training_data(
        index_name, vector_name, docs_count=100, dimensions=4, has_result=True
    )
    # Insert data in bulk
    await bulk_insert(ops_test, app, endpoint, payload)
    return payload_list
