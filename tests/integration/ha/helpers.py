#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
from random import randint
from typing import Dict, List, Optional

from charms.opensearch.v0.models import Node
from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.helpers import http_request


async def app_name(ops_test: OpsTest) -> Optional[str]:
    """Returns the name of the cluster running OpenSearch.

    This is important since not all deployments of the OpenSearch charm have the
    application name "opensearch".
    Note: if multiple clusters are running OpenSearch this will return the one first found.
    """
    status = await ops_test.model.get_status()
    for app in ops_test.model.applications:
        if "opensearch" in status["applications"][app]["charm"]:
            return app

    return None


async def get_elected_cm_unit_id(ops_test: OpsTest, unit_ip: str) -> int:
    """Returns the unit id of the current elected cm node."""
    # get current elected cm node
    resp = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cluster/state/cluster_manager_node",
    )
    cm_node_id = resp.get("cluster_manager_node")
    if not cm_node_id:
        return -1

    # get all nodes
    resp = await http_request(ops_test, "GET", f"https://{unit_ip}:9200/_nodes")
    return int(resp["nodes"][cm_node_id]["name"].split("-")[1])


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
        p_shards = index_id % 2 + 2
        r_shards = 3 if p_shards == 2 else 2
        await http_request(
            ops_test,
            "PUT",
            f"https://{unit_ip}:9200/index_{index_id}",
            {
                "settings": {
                    "index": {"number_of_shards": p_shards, "number_of_replicas": r_shards}
                }
            },
        )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def delete_dummy_indexes(ops_test: OpsTest, unit_ip: str, count: int = 5) -> None:
    """Delete dummy indexes."""
    for index_id in range(count):
        await http_request(
            ops_test,
            "DELETE",
            f"https://{unit_ip}:9200/index_{index_id}",
        )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def create_dummy_docs(ops_test: OpsTest, unit_ip: str, count: int = 5) -> None:
    """Store documents in the dummy indexes."""
    all_docs = ""
    for index_id in range(count):
        for doc_id in range(count * 1000):
            all_docs = (
                f"{all_docs}"
                f'{{"create":{{"_index":"index_{index_id}", "_id":"{doc_id}"}}}}\n'
                f'{{"ProductId": "{1000 + doc_id}", '
                f'"Amount": "{randint(10, 1000)}", '
                f'"Quantity": "{randint(0, 50)}", '
                f'Store_Id": "{randint(1, 250)}"}}\n'
            )

    await http_request(ops_test, "PUT", f"https://{unit_ip}:9200/_bulk", payload=all_docs)


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


async def get_number_of_shards_by_node(ops_test: OpsTest, unit_ip: str) -> Dict[int, int]:
    """Get the number of shards allocated per node."""
    init_cluster_alloc = await cluster_allocation(ops_test, unit_ip)

    result = {}
    for alloc in init_cluster_alloc:
        key = -1
        if alloc["node"] != "UNASSIGNED":
            key = int(alloc["node"].split("-")[1])
        result[key] = int(alloc["shards"])

    return result


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def all_nodes(ops_test: OpsTest, unit_ip: str) -> List[Node]:
    """Fetch the cluster allocation of shards."""
    nodes = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/nodes?format=json",
    )
    return [Node(node["name"], node["node.roles"].split(","), node["ip"]) for node in nodes]


async def assert_continuous_writes_consistency(c_writes: ContinuousWrites) -> None:
    """Continuous writes checks."""
    result = await c_writes.stop()

    assert result.max_stored_id == result.count - 1
    assert result.max_stored_id == result.last_expected_id
