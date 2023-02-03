#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging

from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_delay, wait_fixed


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


async def run_request_on_application_charm(
    ops_test,
    unit_name: str,
    method: str,
    endpoint: str,
    relation_id: str,
    relation_name: str,
    payload: str = None,
    timeout: int = 30,
):
    """Runs the given sql query on the given application charm."""
    client_unit = ops_test.model.units.get(unit_name)
    params = {
        "method": method,
        "endpoint": endpoint,
        "relation-id": relation_id,
        "relation-name": relation_name,
    }
    if payload:
        params["payload"] = json.dumps(payload)
    logging.info(f"running request: \n {endpoint}")
    logging.info(params)
    action = await client_unit.run_action("run-request", **params)
    result = await asyncio.wait_for(action.wait(), timeout)
    logging.info(f"request results: {result.results}")
    return result.results
