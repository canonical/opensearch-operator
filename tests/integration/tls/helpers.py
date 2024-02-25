#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from ..helpers import http_request


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
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
        "HEAD",
        f"https://{unit_ip}:9200/.opendistro_security",
        resp_status_code=True,
    )
    return response == 200


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
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
    response = await http_request(ops_test, "GET", f"https://{unit_ip}:9200")
    return response["name"] == unit_name
