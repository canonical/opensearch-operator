#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
from typing import Dict

import requests
from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from ..helpers import get_secret_by_label, http_request


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


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def get_loaded_tls_certificates(ops_test: OpsTest, unit_ip: str) -> Dict:
    """Returns a dict with the currently loaded TLS certificates for http and transport layer.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the unit of the OpenSearch unit.

    Returns:
        A dict with the currently loaded TLS certificates for http and transport layer.
    """
    url = f"https://{unit_ip}:9200/_plugins/_security/api/ssl/certs"
    admin_secret = await get_secret_by_label(ops_test, "opensearch:app:app-admin")

    with open("admin.cert", "w") as cert:
        cert.write(admin_secret["cert"])

    with open("admin.key", "w") as key:
        key.write(admin_secret["key"])

    response = requests.get(url, cert=("admin.cert", "admin.key"), verify=False)
    return response.json()
