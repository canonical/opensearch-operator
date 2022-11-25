#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
from random import randint
from typing import Dict, List

from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from tests.integration.helpers import http_request


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def get_shards_by_state(ops_test: OpsTest, unit_ip: str) -> Dict[str, List[str]]:
    """Returns all shard statuses for all indexes in the cluster.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the OpenSearch unit.

    Returns:
        Whether all indexes have been successfully replicated and shards started.
    """
    response = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/shards",
    )

    indexes_by_status = {}
    for shard in response:
        state = shard["state"]
        if state not in indexes_by_status:
            indexes_by_status[state] = []

        indexes_by_status[state].append(f"{shard['node']}/{shard['index']}")

    return indexes_by_status


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def create_dummy_indexes(ops_test: OpsTest, unit_ip: str, count: int = 5) -> None:
    """Create indexes."""
    for index_id in range(count):
        await http_request(
            ops_test,
            "PUT",
            f"https://{unit_ip}:9200/index${index_id}",
            {"settings": {"index": {"number_of_shards": 3, "number_of_replicas": 2}}},
        )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def create_dummy_docs(ops_test: OpsTest, unit_ip: str, count: int = 200) -> None:
    """Store documents in the dummy indexes."""
    for index_id in range(count):
        for doc_id in range(count):
            await http_request(
                ops_test,
                "POST",
                f"https://{unit_ip}:9200/index${index_id}/_doc/${doc_id}",
                {
                    "ProductId": f"{1000 + doc_id}",
                    "Amount": f"{randint(10, 1000)}",
                    "Quantity": f"{randint(0, 50)}",
                    "Store_Id": f"{randint(1, 250)}",
                },
            )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def cluster_allocation(ops_test: OpsTest, unit_ip: str) -> List[Dict[str, str]]:
    """Fetch the cluster allocation of shards."""
    return await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/allocation",
    )


async def get_number_of_shards_by_node(ops_test: OpsTest, unit_ip: str) -> Dict[str, int]:
    """Get the number of shards allocated per node."""
    init_cluster_alloc = await cluster_allocation(ops_test, unit_ip)
    return dict(
        [(node_alloc["node"], int(node_alloc["shards"])) for node_alloc in init_cluster_alloc]
    )
