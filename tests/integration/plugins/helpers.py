#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions related to testing the different plugins."""
import json
import logging
import random
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from tests.integration.ha.helpers_data import bulk_insert, create_index
from tests.integration.helpers import APP_NAME, http_request

logger = logging.getLogger(__name__)


def get_systemd_timestamp() -> str:
    """Returns the timestamp from systemd."""
    return subprocess.check_output(["timedatectl", "show", "--property=TimeUSec", "--value"])


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def wait_all_units_restarted_or_fail(ops_test: OpsTest, timestamp: str) -> bool:
    """Waits for all the units of the application to restart or fails.

    Raises:
        Exception: raised if action fails or if timestamp shows restart did not happen yet
    """
    for unit in ops_test.model.applications[APP_NAME].units:
        output = await unit.run(
            "systemctl show snap.opensearch.daemon --property=ActiveEnterTimestamp --value"
        )
        if timestamp >= output.results["Stdout"].rstrip():
            raise Exception()
    return True


def generate_bulk_training_data(
    index_name: str,
    vector_name: str,
    docs_count: int = 100,
    number_dims: int = 4,
    has_result: bool = False,
) -> Tuple[str, List[str]]:
    random.seed("seed")
    print("The seed for randomness is: 'seed'")

    data = random.randbytes(docs_count * number_dims)
    if has_result:
        responses = random.randbytes(docs_count)
    result = ""
    result_list = []
    for i in range(docs_count):
        result += json.dumps({"index": {"_index": index_name, "_id": i}}) + "\n"
        result_list.append([float(data[j]) for j in range(i * number_dims, (i + 1) * number_dims)])
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


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def wait_for_knn_training(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    model_name: str,
) -> bool:
    """Train models."""
    endpoint = f"https://{unit_ip}:9200/_plugins/_knn/models/{model_name}"

    resp = await http_request(ops_test, "GET", endpoint, app=app)
    return "created" in resp.get("state", "")


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
        100, 4, index_name, vector_name, has_result=True
    )
    # Insert data in bulk
    await bulk_insert(ops_test, app, endpoint, payload)
    return payload_list
