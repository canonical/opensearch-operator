#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
import random
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List, Optional, Union

import requests
import yaml
from charms.opensearch.v0.helper_networking import is_reachable
from integration.helpers_deployments import get_application_units, get_unit_hostname
from opensearchpy import OpenSearch
from pytest_operator.plugin import OpsTest
from tenacity import (
    RetryError,
    Retrying,
    retry,
    stop_after_attempt,
    wait_fixed,
    wait_random,
)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]

SERIES = "jammy"
UNIT_IDS = [0, 1, 2]
IDLE_PERIOD = 75

TARBALL_INSTALL_CERTS_DIR = "/etc/opensearch/config/certificates"

MODEL_CONFIG = {
    "logging-config": "<root>=INFO;unit=DEBUG",
    "update-status-hook-interval": "5m",
    "cloudinit-userdata": """postruncmd:
        - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
        - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
        - [ 'sysctl', '-w', 'vm.swappiness=0' ]
        - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    """,
}


logger = logging.getLogger(__name__)


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


@retry(wait=wait_fixed(wait=15), stop=stop_after_attempt(15))
async def run_action(
    ops_test: OpsTest,
    unit_id: Optional[int],
    action_name: str,
    params: Optional[Dict[str, any]] = None,
    app: str = APP_NAME,
) -> SimpleNamespace:
    """Run a charm action.

    Returns:
        A SimpleNamespace with "status, response (results)"
    """
    if unit_id is None:
        online_units = []
        for unit in await get_application_units(ops_test, app):
            if unit.workload_status.value != "active":
                continue

            ping = subprocess.call(
                f"ping -c 1 {unit.ip}".split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if ping == 0:
                online_units.append(unit)

        unit_id = random.choice(online_units).id

    unit_name = [
        unit.name
        for unit in ops_test.model.applications[app].units
        if unit.name.endswith(f"/{unit_id}")
    ][0]

    action = await ops_test.model.units.get(unit_name).run_action(action_name, **(params or {}))
    action = await action.wait()

    return SimpleNamespace(status=action.status or "completed", response=action.results)


async def get_admin_secrets(
    ops_test: OpsTest, unit_id: Optional[int] = None, app: str = APP_NAME
) -> Dict[str, str]:
    """Use the charm action to retrieve the admin password and chain.

    Returns:
        Dict with the admin and cert chain stored on the peer relation databag.
    """
    # can retrieve from any unit running unit, so we pick the first
    return (await run_action(ops_test, unit_id, "get-password", app=app)).response


def get_application_unit_names(ops_test: OpsTest, app: str = APP_NAME) -> List[str]:
    """List the unit names of an application.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        list of current unit names of the application
    """
    return [unit.name.replace("/", "-") for unit in ops_test.model.applications[app].units]


def get_application_unit_ids(ops_test: OpsTest, app: str = APP_NAME) -> List[int]:
    """List the unit IDs of an application.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        list of current unit ids of the application
    """
    return [int(unit.name.split("/")[1]) for unit in ops_test.model.applications[app].units]


def get_application_unit_status(ops_test: OpsTest, app: str = APP_NAME) -> Dict[int, str]:
    """List the unit statuses of an application.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        list of current unit statuses of the application
    """
    units = ops_test.model.applications[app].units

    result = {}
    for unit in units:
        result[int(unit.name.split("/")[1])] = unit.workload_status.value

    return result


async def get_application_unit_ips(ops_test: OpsTest, app: str = APP_NAME) -> List[str]:
    """List the unit IPs of an application.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        list of current unit IPs of the application
    """
    return [unit.ip for unit in await get_application_units(ops_test, app)]


async def get_application_unit_ips_names(ops_test: OpsTest, app: str = APP_NAME) -> Dict[str, str]:
    """List the units of an application by name and corresponding IPs.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        Dictionary unit_name / unit_ip, of the application
    """
    result = {}
    for unit in await get_application_units(ops_test, app):
        result[unit.name] = unit.ip

    return result


async def get_application_unit_ids_ips(ops_test: OpsTest, app: str = APP_NAME) -> Dict[int, str]:
    """List the units of an application by id and corresponding IP.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        Dictionary unit_id / unit_ip, of the application
    """
    result = {}
    for unit in await get_application_units(ops_test, app):
        result[unit.id] = unit.ip

    return result


async def get_application_unit_ids_hostnames(
    ops_test: OpsTest, app: str = APP_NAME
) -> Dict[int, str]:
    """List the units of an application by id and corresponding host name."""
    result = {}
    for unit in ops_test.model.applications[app].units:
        unit_id = int(unit.name.split("/")[1])
        result[unit_id] = await get_unit_hostname(ops_test, unit_id, app)

    return result


async def get_leader_unit_ip(ops_test: OpsTest, app: str = APP_NAME) -> str:
    """Helper function that retrieves the leader unit."""
    for unit in await get_application_units(ops_test, app):
        if unit.is_leader:
            return unit.ip


async def get_leader_unit_id(ops_test: OpsTest, app: str = APP_NAME) -> int:
    """Helper function that retrieves the leader unit ID."""
    leader_unit = None
    for unit in ops_test.model.applications[app].units:
        if await unit.is_leader_from_status():
            leader_unit = unit
            break

    return int(leader_unit.name.split("/")[1])


async def get_controller_hostname(ops_test: OpsTest) -> str:
    """Return controller machine hostname."""
    _, raw_controller, _ = await ops_test.juju("show-controller")

    controller = yaml.safe_load(raw_controller.strip())

    return [
        machine.get("instance-id")
        for machine in controller[ops_test.controller_name]["controller-machines"].values()
    ][0]


async def get_reachable_unit_ips(ops_test: OpsTest, app: str = APP_NAME) -> List[str]:
    """Helper function to retrieve the IP addresses of all online units."""
    result = []
    for ip in await get_application_unit_ips(ops_test, app):
        if not is_reachable(ip, 9200):
            continue

        if await is_up(ops_test, ip, retries=1):
            result.append(ip)

    return result


async def get_reachable_units(ops_test: OpsTest, app: str = APP_NAME) -> Dict[int, str]:
    """Helper function to retrieve a dict of id/IP addresses of all online units."""
    result = {}
    for unit in await get_application_units(ops_test, app):
        if not is_reachable(unit.ip, 9200):
            continue

        if not (await is_up(ops_test, unit.ip, retries=1)):
            continue

        result[unit.id] = unit.ip

    return result


async def http_request(
    ops_test: OpsTest,
    method: str,
    endpoint: str,
    payload: Optional[Union[str, Dict[str, any]]] = None,
    resp_status_code: bool = False,
    verify=True,
    user_password: Optional[str] = None,
    app: str = APP_NAME,
    json_resp: bool = True,
):
    """Makes an HTTP request.

    Args:
        ops_test: The ops test framework instance.
        method: the HTTP method (GET, POST, HEAD etc.)
        endpoint: the url to be called.
        payload: the body of the request if any.
        resp_status_code: whether to only return the http response code.
        verify: whether verify certificate chain or not
        user_password: use alternative password than the admin one in the secrets.
        app: the name of the current application.
        json_resp: return a json response or simply log

    Returns:
        A json object.
    """
    admin_secrets = await get_admin_secrets(ops_test, app=app)

    # fetch the cluster info from the endpoint of this unit
    with requests.Session() as session, tempfile.NamedTemporaryFile(mode="w+") as chain:
        chain.write(admin_secrets["ca-chain"])
        chain.seek(0)

        logger.info(f"Calling: {method} -- {endpoint}")

        request_kwargs = {
            "method": method,
            "url": endpoint,
            "timeout": (17, 17),
        }
        if json_resp:
            request_kwargs["headers"] = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

        if isinstance(payload, str):
            request_kwargs["data"] = payload
        elif isinstance(payload, dict):
            request_kwargs["data"] = json.dumps(payload)

        session.auth = ("admin", user_password or admin_secrets["password"])

        request_kwargs["verify"] = chain.name if verify else False
        resp = session.request(**request_kwargs)

        if resp.status_code == 503:
            logger.debug("\n\n\n\n -- Error 503 -- \n")
            await debug_failed_unit(ops_test, app, endpoint)

        if resp_status_code:
            return resp.status_code

        if json_resp:
            return resp.json()

        logger.info(f"\n{resp.text}")
        return resp


async def debug_failed_unit(ops_test: OpsTest, app: str, endpoint: str) -> None:
    """Print the logs of a unit failing with a certain set of statuses."""
    unit_ip = endpoint[8:].split(":")[0]

    ids_ips = await get_application_unit_ids_ips(ops_test, app=app)
    unit_id = [u_id for u_id, u_ip in ids_ips.items() if u_ip == unit_ip][0]

    root = "/var/snap/opensearch"
    files_to_debug = [
        f"{root}/common/logs/{app}-{ops_test.model_name}.log",
        f"{root}/current/config/opensearch.yml",
        f"{root}/current/config/unicast_hosts.txt",
    ]
    for f in files_to_debug:
        logger.debug(f"{f}:\n")

        get_logs_cmd = f"run --unit {app}/{unit_id} -- sudo cat {f}"
        _, out, err = await ops_test.juju(*get_logs_cmd.split())
        logger.debug(f"out:\n{out}\n---\nerr:\n{err}")

        logger.debug("\n\n------------------\n\n")


def opensearch_client(
    hosts: List[str], user_name: str, password: str, cert_path: str
) -> OpenSearch:
    """Build an opensearch client."""
    return OpenSearch(
        hosts=[{"host": ip, "port": 9200} for ip in hosts],
        http_auth=(user_name, password),
        http_compress=True,
        sniff_on_start=True,  # sniff before doing anything
        sniff_on_connection_fail=True,  # refresh nodes after a node fails to respond
        sniffer_timeout=60,  # and also every 60 seconds
        use_ssl=True,  # turn on ssl
        verify_certs=True,  # make sure we verify SSL certificates
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        ca_certs=cert_path,  # cert path on disk
    )


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def cluster_health(
    ops_test: OpsTest, unit_ip: str, wait_for_green_first: bool = False
) -> Dict[str, any]:
    """Fetch the cluster health."""
    if wait_for_green_first:
        try:
            return await http_request(
                ops_test,
                "GET",
                f"https://{unit_ip}:9200/_cluster/health?wait_for_status=green&timeout=1m",
            )
        except requests.HTTPError:
            # it timed out, settle with current status, fetched next without the 1min wait
            pass

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


async def is_up(ops_test: OpsTest, unit_ip: str, retries: int = 25) -> bool:
    """Return if node up."""
    try:
        for attempt in Retrying(stop=stop_after_attempt(retries), wait=wait_fixed(wait=15)):
            with attempt:
                await http_request(ops_test, "GET", f"https://{unit_ip}:9200/")
                return True
    except RetryError:
        return False


async def scale_application(
    ops_test: OpsTest, application_name: str, count: int, timeout=1000, idle_period=20
) -> None:
    """Scale a given application to a specific unit count.

    Args:
        ops_test: The ops test framework instance
        application_name: The name of the application
        count: The desired number of units to scale to
        timeout: Time to wait for application to become stable
        idle_period: The length of time we watch an application to ensure it stays in an idle
            status.
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

    await ops_test.model.wait_for_idle(
        apps=[application_name],
        status="active",
        timeout=timeout,
        wait_for_exact_units=count,
        idle_period=idle_period,
    )


def juju_version_major() -> int:
    """Fetch the juju version."""
    version = subprocess.run(["juju", "--version"], check=True, stdout=subprocess.PIPE).stdout
    return int(version.strip().decode("utf-8").split(".")[0])
