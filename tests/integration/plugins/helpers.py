#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions related to testing the different plugins."""
import json
import logging
import random
from typing import Any, Dict, List, Optional

from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from tests.integration.ha.helpers_data import bulk_insert, create_index
from tests.integration.helpers import http_request

logger = logging.getLogger(__name__)


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def wait_all_units_restarted_or_fail(active_since: Dict[Any, str]) -> Dict[Any, str]:
    """Waits for all the units of the application to restart or fails.

    Args:
        active_since: dict, dictionary containing each unit and its latest timestamp as string.
                            if unit's value is None, then set found timestamp.

    Raises:
        Exception: raised if action fails or if timestamp shows restart did not happen yet
                   https://github.com/juju/python-libjuju/blob/\
                       48570bb8d51d38c430d12b86e39706ffd6969fcc/juju/unit.py#L301
    """
    result = {}
    for unit, timestamp in active_since.items():
        action = await unit.run_action("active-since")
        output = await action.wait()
        timestamp = output.results["timestamp"]
        if not active_since[unit] or active_since[unit] < timestamp:
            result[unit] = timestamp
        else:
            raise Exception()
    return result


def generate_bulk_training_data(
    n: int, ndims: int, index_name: str, vector_name: str, has_result: bool = False
) -> str:
    random.seed("seed")
    print("The seed for randomness is: 'seed'")

    data = random.randbytes(n * ndims)
    if has_result:
        responses = random.randbytes(n)
    result = ""
    result_list = []
    for i in range(n):
        result += json.dumps({"index": {"_index": index_name, "_id": i}}) + "\n"
        result_list.append([float(data[j]) for j in range(i * ndims, (i + 1) * ndims)])
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

    resp = await http_request(ops_test, "POST", endpoint, payload=payload, app=app)
    return resp


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
    ops_test, app, endpoint, index_name, shards, vector_name, model_name=None
):
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


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def search(
    ops_test: OpsTest,
    app: str,
    unit_ip: str,
    index_name: str,
    query: Optional[Dict[str, Any]] = None,
    preference: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Search documents."""
    endpoint = f"https://{unit_ip}:9200/{index_name}/_search"
    if preference:
        endpoint = f"{endpoint}?preference={preference}"

    resp = await http_request(ops_test, "GET", endpoint, payload=query, app=app)
    return resp["hits"]["hits"]