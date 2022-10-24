#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import List

from pytest_operator.plugin import OpsTest
from tenacity import retry, retry_if_not_result, stop_after_attempt, wait_exponential

from tests.integration.helpers import http_request


@retry(
    wait=wait_exponential(multiplier=1, min=2, max=30),
    stop=stop_after_attempt(15),
    retry_error_callback=(lambda state: state.outcome.result()),
    retry=retry_if_not_result(lambda result: True if result else False),
)
async def check_security_index_initialised(ops_test: OpsTest, unit_ip: str) -> bool:
    """Returns whether the security index is initialised.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the unit of the OpenSearch unit.

    Returns:
        Whether The security index is initialised.
    """
    response = await http_request(
        ops_test,
        f"https://{unit_ip}:9200/.opendistro_security",
        "HEAD",
        resp_status_code=True,
    )
    return response == 200


@retry(
    wait=wait_exponential(multiplier=1, min=2, max=30),
    stop=stop_after_attempt(15),
    retry_error_callback=(lambda state: state.outcome.result()),
    retry=retry_if_not_result(lambda result: True if result else False),
)
async def check_unit_tls_configured(ops_test: OpsTest, unit_ip: str, unit_name: str) -> bool:
    """Returns whether TLS is enabled on the specific OpenSearch unit.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the unit of the OpenSearch unit.
        unit_name: The name of the OpenSearch unit.

    Returns:
        Whether the node is up: no TLS config issues and TLS on HTTP layer successful.
    """
    response = await http_request(ops_test, f"https://{unit_ip}:9200", "GET")
    return response["name"] == unit_name


@retry(
    wait=wait_exponential(multiplier=1, min=2, max=30),
    stop=stop_after_attempt(15),
    retry_error_callback=(lambda state: state.outcome.result()),
    retry=retry_if_not_result(lambda result: True if result else False),
)
async def check_cluster_formation_successful(
    ops_test: OpsTest, unit_ip: str, unit_names: List[str]
) -> bool:
    """Returns whether TLS is enabled on the specific OpenSearch unit.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the unit of the OpenSearch unit.
        unit_names: The list of unit names in the cluster.

    Returns:
        Whether TLS is well configured.
    """
    unit_names_set = set(unit_names)

    response = await http_request(ops_test, f"https://{unit_ip}:9200/_nodes", "GET")
    if "_nodes" not in response or "nodes" not in response:
        return False

    successful_nodes = response["_nodes"]["successful"]
    if successful_nodes < len(unit_names):
        return False

    for node_id, node_desc in response["nodes"].items():
        node_name = node_desc["name"]
        if node_name not in unit_names_set:
            return False

        unit_names_set.remove(node_name)

    return len(unit_names_set) == 0
