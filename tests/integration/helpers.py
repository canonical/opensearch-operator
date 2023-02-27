#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List, Optional, Union

import requests
import yaml
from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]

SERIES = "jammy"
UNIT_IDS = [0, 1, 2]

TARBALL_INSTALL_CERTS_DIR = "/etc/opensearch/config/certificates"

MODEL_CONFIG = {
    "logging-config": "<root>=INFO;unit=DEBUG",
    "update-status-hook-interval": "1m",
    "cloudinit-userdata": """postruncmd:
        - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
        - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
        - [ 'sysctl', '-w', 'vm.swappiness=0' ]
        - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    """,
}


logger = logging.getLogger(__name__)


async def run_action(
    ops_test: OpsTest, unit_id: int, action_name: str, params: Optional[Dict[str, any]] = None
) -> SimpleNamespace:
    """Run a charm action.

    Returns:
        A SimpleNamespace with "status, response (results)"
    """
    unit_name = ops_test.model.applications[APP_NAME].units[unit_id].name

    action = await ops_test.model.units.get(unit_name).run_action(action_name, **(params or {}))
    action = await action.wait()

    return SimpleNamespace(status=action.status or "completed", response=action.results)


async def get_admin_secrets(ops_test: OpsTest, unit_id: int = 0) -> Dict[str, str]:
    """Use the charm action to retrieve the admin password and chain.

    Returns:
        Dict with the admin and cert chain stored on the peer relation databag.
    """
    # can retrieve from any unit running unit, so we pick the first
    return (await run_action(ops_test, unit_id, "get-password")).response


def get_application_unit_names(ops_test: OpsTest) -> List[str]:
    """List the unit names of an application.

    Args:
        ops_test: The ops test framework instance

    Returns:
        list of current unit names of the application
    """
    return [unit.name.replace("/", "-") for unit in ops_test.model.applications[APP_NAME].units]


def get_application_unit_ids(ops_test: OpsTest) -> List[int]:
    """List the unit IDs of an application.

    Args:
        ops_test: The ops test framework instance

    Returns:
        list of current unit ids of the application
    """
    return [int(unit.name.split("/")[1]) for unit in ops_test.model.applications[APP_NAME].units]


def get_application_unit_status(ops_test: OpsTest) -> Dict[int, str]:
    """List the unit statuses of an application.

    Args:
        ops_test: The ops test framework instance

    Returns:
        list of current unit statuses of the application
    """
    units = ops_test.model.applications[APP_NAME].units

    result = {}
    for unit in units:
        result[int(unit.name.split("/")[1])] = unit.workload_status

    return result


def get_application_unit_ips(ops_test: OpsTest) -> List[str]:
    """List the unit IPs of an application.

    Args:
        ops_test: The ops test framework instance

    Returns:
        list of current unit IPs of the application
    """
    return [unit.public_address for unit in ops_test.model.applications[APP_NAME].units]


def get_application_unit_ips_names(ops_test: OpsTest) -> Dict[str, str]:
    """List the units of an application by name and corresponding IPs.

    Args:
        ops_test: The ops test framework instance

    Returns:
        Dictionary unit_name / unit_ip, of the application
    """
    result = {}
    for unit in ops_test.model.applications[APP_NAME].units:
        result[unit.name.replace("/", "-")] = unit.public_address

    return result


async def get_leader_unit_ip(ops_test: OpsTest) -> str:
    """Helper function that retrieves the leader unit."""
    leader_unit = None
    for unit in ops_test.model.applications[APP_NAME].units:
        if await unit.is_leader_from_status():
            leader_unit = unit
            break

    return leader_unit.public_address


async def get_leader_unit_id(ops_test: OpsTest) -> int:
    """Helper function that retrieves the leader unit ID."""
    leader_unit = None
    for unit in ops_test.model.applications[APP_NAME].units:
        if await unit.is_leader_from_status():
            leader_unit = unit
            break

    return int(leader_unit.name.split("/")[1])


async def http_request(
    ops_test: OpsTest,
    method: str,
    endpoint: str,
    payload: Optional[Union[str, Dict[str, any]]] = None,
    resp_status_code: bool = False,
    verify=True,
    user_password: Optional[str] = None,
):
    """Makes an HTTP request.

    Args:
        ops_test: The ops test framework instance.
        method: the HTTP method (GET, POST, HEAD etc.)
        endpoint: the url to be called.
        payload: the body of the request if any.
        resp_status_code: whether to only return the http response code.
        user_password: use alternative password than the admin one in the secrets.

    Returns:
        A json object.
    """
    admin_secrets = await get_admin_secrets(ops_test)

    # fetch the cluster info from the endpoint of this unit
    with requests.Session() as session, tempfile.NamedTemporaryFile(mode="w+") as chain:
        chain.write(admin_secrets["ca-chain"])
        chain.seek(0)

        request_kwargs = {
            "method": method,
            "url": endpoint,
            "headers": {"Accept": "application/json", "Content-Type": "application/json"},
        }
        if isinstance(payload, str):
            request_kwargs["data"] = payload
        elif isinstance(payload, dict):
            request_kwargs["data"] = json.dumps(payload)

        session.auth = ("admin", user_password or admin_secrets["password"])

        request_kwargs["verify"] = chain.name if verify else False
        resp = session.request(**request_kwargs)

        if resp_status_code:
            return resp.status_code

        return resp.json()


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def cluster_health(ops_test: OpsTest, unit_ip: str) -> Dict[str, any]:
    """Fetch the cluster health."""
    return await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cluster/health",
    )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def check_cluster_formation_successful(
    ops_test: OpsTest, unit_ip: str, unit_names: List[str]
) -> bool:
    """Returns whether the cluster formation was successful and all nodes successfully joined.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the unit of the OpenSearch unit.
        unit_names: The list of unit names in the cluster.

    Returns:
        Whether The cluster formation is successful.
    """
    response = await http_request(ops_test, "GET", f"https://{unit_ip}:9200/_nodes")
    if "_nodes" not in response or "nodes" not in response:
        return False

    successful_nodes = response["_nodes"]["successful"]
    if successful_nodes < len(unit_names):
        return False

    registered_nodes = [node_desc["name"] for node_desc in response["nodes"].values()]
    return set(unit_names) == set(registered_nodes)


async def scale_application(ops_test: OpsTest, application_name: str, count: int) -> None:
    """Scale a given application to a specific unit count.

    Args:
        ops_test: The ops test framework instance
        application_name: The name of the application
        count: The desired number of units to scale to
    """
    application = ops_test.model.applications[application_name]
    change = count - len(application.units)
    if change > 0:
        await application.add_units(change)
    elif change < 0:
        units = [unit.name for unit in application.units[0:-change]]
        await application.destroy_units(*units)
    else:
        return

    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[application_name], status="active", timeout=1000, wait_for_exact_units=count
        )
