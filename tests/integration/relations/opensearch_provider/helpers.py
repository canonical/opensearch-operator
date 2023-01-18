#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_delay, wait_fixed

async def check_new_relation(ops_test: OpsTest):
    """Smoke test to check relation is online."""
    raise NotImplementedError


def wait_for_relation_joined_between(
    ops_test: OpsTest, endpoint_one: str, endpoint_two: str
) -> None:
    """Wait for relation to be be created before checking if it's waiting or idle.

    Args:
        ops_test: running OpsTest instance
        endpoint_one: one endpoint of the relation. Doesn't matter if it's provider or requirer.
        endpoint_two: the other endpoint of the relation.
    """
    try:
        for attempt in Retrying(stop=stop_after_delay(3 * 60), wait=wait_fixed(3)):
            with attempt:
                if new_relation_joined(ops_test, endpoint_one, endpoint_two):
                    break
    except RetryError:
        assert False, "New relation failed to join after 3 minutes."


def new_relation_joined(ops_test: OpsTest, endpoint_one: str, endpoint_two: str) -> bool:
    for rel in ops_test.model.relations:
        endpoints = [endpoint.name for endpoint in rel.endpoints]
        if endpoint_one in endpoints and endpoint_two in endpoints:
            return True
    return False
