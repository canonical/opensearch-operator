#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helper functions for data related tests, such as indexing, searching etc.."""
from random import randint
from typing import Any, Dict, Optional

from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from tests.integration.helpers import http_request


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
async def create_index(
    ops_test: OpsTest, unit_ip: str, index_name: str, p_shards: int = 1, r_shards: int = 1
) -> None:
    """Create an index with a set number of primary and replica shards."""
    await http_request(
        ops_test,
        "PUT",
        f"https://{unit_ip}:9200/{index_name}",
        {"settings": {"index": {"number_of_shards": p_shards, "number_of_replicas": r_shards}}},
    )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def index_doc(
    ops_test: OpsTest,
    unit_ip: str,
    index_name: str,
    doc_id: int,
    doc: Optional[Dict[str, any]] = None,
    refresh: bool = True,
) -> None:
    """Index a simple document."""
    if not doc:
        doc = default_doc(index_name, doc_id)

    await http_request(
        ops_test, "PUT", f"https://{unit_ip}:9200/{index_name}/_doc/{doc_id}", payload=doc
    )

    # a refresh makes the indexed data available for search, runs by default every 30 sec,
    # but we can manually trigger it like below
    if refresh:
        await http_request(ops_test, "POST", f"https://{unit_ip}:9200/{index_name}/_refresh")


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def get_doc(ops_test: OpsTest, unit_ip: str, index_name: str, doc_id: int) -> Dict[str, Any]:
    """Index a simple document."""
    return await http_request(
        ops_test, "GET", f"https://{unit_ip}:9200/{index_name}/_doc/{doc_id}"
    )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def delete_doc(ops_test: OpsTest, unit_ip: str, index_name: str, doc_id: int) -> None:
    """Index a simple document."""
    await http_request(
        ops_test,
        "DELETE",
        f"https://{unit_ip}:9200/{index_name}/_doc/{doc_id}",
    )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def delete_index(ops_test: OpsTest, unit_ip: str, index_name: str) -> None:
    """Index a simple document."""
    await http_request(
        ops_test,
        "DELETE",
        f"https://{unit_ip}:9200/{index_name}/",
    )


def default_doc(index_name: str, doc_id: int) -> Dict[str, Any]:
    """Return a default document used in the tests."""
    return {"title": f"title_{doc_id}", "val": doc_id, "path": f"{index_name}/{doc_id}"}
