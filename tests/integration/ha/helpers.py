#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
from typing import Dict, List

from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from tests.integration.helpers import http_request


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def get_shards_by_status(ops_test: OpsTest, unit_ip: str) -> Dict[str, List[str]]:
    """Returns whether all shards are marked as STARTED.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the OpenSearch unit.

    Returns:
        Whether all indexes have been successfully replicated and shards started.
    """
    response = await http_request(
        ops_test,
        f"https://{unit_ip}:9200/_cat/shards",
        "GET",
    )

    indexes_by_status = {}
    for shard in response:
        status = shard["status"]
        if status not in indexes_by_status:
            indexes_by_status[status] = []

        indexes_by_status[status].append(f"{shard['node']}/{shard['index']}")

    return indexes_by_status
