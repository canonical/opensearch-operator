#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import yaml
from pytest_operator.plugin import OpsTest

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]

SERIES = "jammy"
UNIT_IDS = [0, 1, 2]

TARBALL_INSTALL_CERTS_DIR = "/etc/opensearch/config/certificates"


async def get_admin_password(ops_test: OpsTest) -> str:
    """Use the charm action to retrieve the password from provided unit.

    Returns:
        String with the password stored on the peer relation databag.
    """
    # can retrieve from any unit running unit, so we pick the first
    unit_name = ops_test.model.applications[APP_NAME].units[0].name
    unit_id = unit_name.split("/")[1]

    action = await ops_test.model.units.get(f"{APP_NAME}/{unit_id}").run_action(
        "get-admin-password"
    )
    action = await action.wait()
    return action.results["password"]


def get_application_unit_names(ops_test: OpsTest) -> List[str]:
    """List the unit names of an application.

    Args:
        ops_test: The ops test framework instance

    Returns:
        list of current unit names of the application
    """
    return [unit.name.replace("/", "-") for unit in ops_test.model.applications[APP_NAME].units]


def get_application_unit_ips(ops_test: OpsTest) -> List[str]:
    """List the unit IPs of an application.

    Args:
        ops_test: The ops test framework instance

    Returns:
        list of current unit IPs of the application
    """
    return [unit.public_address for unit in ops_test.model.applications[APP_NAME].units]


def get_application_unit_ips_names(ops_test: OpsTest) -> List[Tuple[str, str]]:
    """List the unit IPs, Names of an application.

    Args:
        ops_test: The ops test framework instance

    Returns:
        list of tuples of current unit IPs, Names of the application
    """
    return [
        (unit.public_address, unit.name) for unit in ops_test.model.applications[APP_NAME].units
    ]


async def get_leader_unit_ip(ops_test: OpsTest) -> str:
    """Helper function that retrieves the leader unit."""
    leader_unit = None
    for unit in ops_test.model.applications[APP_NAME].units:
        if await unit.is_leader_from_status():
            leader_unit = unit
            break

    return leader_unit.public_address


async def http_request(
    ops_test: OpsTest,
    endpoint: str,
    method: str,
    payload: Optional[Dict[str, any]] = None,
    resp_status_code: bool = False,
):
    """Makes an HTTP request.

    Args:
        ops_test: The ops test framework instance.
        endpoint: the url to be called.
        method: the HTTP method (GET, POST etc.)
        payload: the body of the request if any.
        resp_status_code: whether to only return the http response code.

    Returns:
        A json object.
    """
    admin_password = await get_admin_password(ops_test)

    # fetch the cluster info from the endpoint of this unit
    with requests.Session() as s:
        s.auth = ("admin", admin_password)
        resp = s.request(
            method=method,
            url=endpoint,
            data=payload,
            verify=f"{TARBALL_INSTALL_CERTS_DIR}/chain.pem",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

        if resp_status_code:
            return resp.status_code

        return resp.json()
