#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
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

from ..ha.helpers_data import bulk_insert, create_index
from ..helpers import http_request

logger = logging.getLogger(__name__)


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
        extra_index_settings = {"knn": "true"}
    else:
        extra_mappings = {
            "properties": {
                vector_name: {
                    "type": "knn_vector",
                    "dimension": 4,
                }
            }
        }
        extra_index_settings = {}

    await create_index(
        ops_test,
        app,
        endpoint,
        index_name,
        r_shards=shards,
        extra_index_settings=extra_index_settings,
        extra_mappings=extra_mappings,
    )
    payload, payload_list = generate_bulk_training_data(
        index_name, vector_name, docs_count=100, dimensions=4, has_result=True
    )
    # Insert data in bulk
    await bulk_insert(ops_test, app, endpoint, payload)
    return payload_list
