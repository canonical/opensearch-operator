#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
import json
import logging
import random
import socket
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import requests
import yaml
from dateutil.parser import parse
from opensearchpy import OpenSearch
from pytest_operator.plugin import OpsTest
from tenacity import (
    retry,
    stop_after_attempt,
    wait_fixed,
    wait_random,
)

from tests.helpers import Substrate
from tests.integration.conftest import CLIENT_CHARM

from .helpers_deployments import get_application_units

METADATA = yaml.safe_load(Path("./machines/metadata.yaml").read_text())
APP_NAME = METADATA["name"]

SERIES = "jammy"
UNIT_IDS = [0, 1, 2]
IDLE_PERIOD = 75

TARBALL_INSTALL_CERTS_DIR = "/etc/opensearch/config/certificates"

CONFIG_OPTS = {"profile": "testing"}

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


class Status:
    """Model class for status."""

    def __init__(self, value: str, since: str, message: Optional[str] = None):
        self.value = value
        self.since = parse(since, ignoretz=True)
        self.message = message


class Unit:
    """Model class for a Unit, with properties widely used."""

    def __init__(
        self,
        id: int,
        short_name: str,
        name: str,
        ip: str,
        hostname: str,
        is_leader: bool,
        machine_id: int,
        workload_status: Status,
        agent_status: Status,
        app_status: Status,
    ):
        self.id = id
        self.short_name = short_name
        self.name = name
        self.ip = ip
        self.hostname = hostname
        self.is_leader = is_leader
        self.machine_id = machine_id
        self.workload_status = workload_status
        self.agent_status = agent_status
        self.app_status = app_status

    def dump(self) -> Dict[str, Any]:
        """To json."""
        result = {}
        for key, val in vars(self).items():
            result[key] = vars(val) if isinstance(val, Status) else val
        return result


class Shard:
    """Class for holding a shard."""

    def __init__(self, index: str, num: int, is_prim: bool, node_id: str, unit_id: int, app: str):
        self.index = index
        self.num = num
        self.is_prim = is_prim
        self.node_id = node_id
        self.unit_id = unit_id
        self.app = app


def is_reachable(host: str, port: int) -> bool:
    """Attempting a socket connection to a host/port."""
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((host, port))
        return True
    except Exception as e:
        logger.debug(f"Connection to {host}:{port} fails with: {e}")
        return False
    finally:
        s.close()


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def get_shards_by_index(
    ops_test: OpsTest, unit_ip: str, index_name: str, app: str = APP_NAME
) -> list[Shard]:
    """Returns the list of shards and their location in cluster for an index.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the OpenSearch unit.
        index_name: the name of the index.
        app: The name of the application.

    Returns:
        List of shards.
    """
    response = await http_request(
        ops_test, "GET", f"https://{unit_ip}:9200/{index_name}/_search_shards", app=app
    )

    nodes = response["nodes"]

    result = []
    for shards_collection in response["shards"]:
        for shard in shards_collection:
            node_name_split = nodes[shard["node"]]["name"].split(".")[0].split("-")
            result.append(
                Shard(
                    index=index_name,
                    num=shard["shard"],
                    is_prim=shard["primary"],
                    node_id=shard["node"],
                    unit_id=int(node_name_split[-1]),
                    app="-".join(node_name_split[:-1]),
                )
            )

    return result


@retry(wait=wait_fixed(wait=15), stop=stop_after_attempt(15))
async def run_action(
    ops_test: OpsTest,
    unit_id: Optional[int],
    action_name: str,
    params: Optional[Dict[str, Any]] = None,
    app: str = APP_NAME,
) -> SimpleNamespace:
    """Run a charm action.

    Returns:
        A SimpleNamespace with "status, response (results)"
    """
    if unit_id is None:
        # On K8s there is no SSH server in the workload pod, so probing port 22 to
        # decide whether a unit is reachable always fails and leaves us with no
        # candidate units. Only run the SSH reachability check on VM.
        is_k8s = ops_test.request.config.option.substrate == "k8s"

        online_units = []
        for unit in await get_application_units(ops_test, app):
            if unit.workload_status.value != "active":
                continue

            if is_k8s:
                online_units.append(unit)
                continue

            ping = subprocess.call(
                f"nc -zv {unit.ip} 22".split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if ping == 0:
                online_units.append(unit)

        if not online_units:
            raise RuntimeError(f"No active/reachable units found for application {app!r}")

        unit_id = random.choice(online_units).id

    unit_name = [
        unit.name
        for unit in ops_test.model.applications[app].units
        if unit.name.endswith(f"/{unit_id}")
    ][0]

    action = await ops_test.model.units.get(unit_name).run_action(action_name, **(params or {}))
    action = await action.wait()

    return SimpleNamespace(status=action.status or "completed", response=action.results)


async def get_secrets(
    ops_test: OpsTest, unit_id: Optional[int] = None, username: str = "admin", app: str = APP_NAME
) -> Dict[str, str]:
    """Use the charm action to retrieve the admin password and chain.

    Returns:
        Dict with the admin and cert chain stored on the peer relation databag.
    """
    # can retrieve from any unit running unit, so we pick the first
    return (
        await run_action(ops_test, unit_id, "get-password", {"username": username}, app=app)
    ).response


def get_application_unit_ids(ops_test: OpsTest, app: str = APP_NAME) -> List[int]:
    """List the unit IDs of an application.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        list of current unit ids of the application
    """
    return [int(unit.name.split("/")[1]) for unit in ops_test.model.applications[app].units]


async def get_application_unit_ips(ops_test: OpsTest, app: str = APP_NAME) -> List[str]:
    """List the unit IPs of an application.

    Args:
        ops_test: The ops test framework instance
        app: the name of the app

    Returns:
        list of current unit IPs of the application
    """
    return [unit.ip for unit in await get_application_units(ops_test, app)]


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


async def _find_k8s_unit_for_endpoint(
    ops_test: OpsTest, endpoint: str, app: str
) -> Optional[Unit]:
    """Return the K8s unit matching the endpoint host, if any."""
    if ops_test.request.config.option.substrate != "k8s":
        return None

    hostname = urlparse(endpoint).hostname
    if not hostname:
        return None

    for unit in await get_application_units(ops_test, app):
        # On K8s the pod hostname is the Juju short unit name, e.g. `opensearch-0`.
        # We use that as the signal to run requests from inside the pod so TLS can
        # use the pod DNS name rather than the external pod IP.
        if unit.ip == hostname:
            return unit

    return None


def _model_name(ops_test: OpsTest) -> str:
    """Return the active Juju model name from pytest-operator."""
    return getattr(ops_test, "model_name", None) or ops_test.model.info.name


def _request_path(endpoint: str) -> str:
    """Return the path and query string for an HTTP endpoint."""
    parsed_endpoint = urlparse(endpoint)
    path = parsed_endpoint.path or "/"
    return f"{path}?{parsed_endpoint.query}" if parsed_endpoint.query else path


def _k8s_unit_fqdn(ops_test: OpsTest, app: str, unit: Unit) -> str:
    """Return the fully qualified domain name for a K8s unit"""
    return f"{unit.short_name}.{app}-endpoints.{_model_name(ops_test)}.svc.cluster.local"


def _http_request_headers(
    json_resp: bool,
    extra_headers: Optional[Dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build headers used by http_request."""
    headers: dict[str, Any] = {}
    if json_resp:
        headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
    if extra_headers:
        headers.update(extra_headers)
    return headers


async def http_request(  # noqa: C901
    ops_test: OpsTest,
    method: str,
    endpoint: str,
    payload: Optional[Union[str, Dict[str, Any]]] = None,
    resp_status_code: bool = False,
    verify=True,
    user: Optional[str] = "admin",
    user_password: Optional[str] = None,
    app: str = APP_NAME,
    json_resp: bool = True,
    extra_headers: Optional[Dict[str, Any]] = None,
    timeout: float = 30.0,
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
    admin_secrets = await get_secrets(ops_test, app=app)
    if ops_test.request.config.option.substrate == "k8s":
        k8s_unit = await _find_k8s_unit_for_endpoint(ops_test, endpoint, app)
        if not k8s_unit:
            raise RuntimeError(
                f"No unit found for endpoint {endpoint}. Cannot make request from {CLIENT_CHARM}."
            )
        # K8s requests that start from a pod IP are executed from inside the
        # cluster so they can use the stable unit service DNS name with strict TLS.
        logger.info(
            f"Calling through {CLIENT_CHARM} for {k8s_unit.name}: {method} - {_k8s_unit_fqdn(ops_test, app, k8s_unit)} route: {_request_path(endpoint)}"
        )
        params: dict[str, Any] = {
            "method": method,
            "route": _request_path(endpoint),
            "host": _k8s_unit_fqdn(ops_test, app, k8s_unit),
            "ca_cert": base64.b64encode(admin_secrets["ca-chain"].encode()).decode(),
            "timeout": int(timeout),
        }
        if payload is not None:
            params["body"] = json.dumps(payload)
        if user is not None:
            params["username"] = user
            params["password"] = user_password or admin_secrets["password"]
        if not verify:
            params["verify"] = False
        if headers := _http_request_headers(json_resp, extra_headers):
            params["headers"] = json.dumps(headers)

        action = await run_action(
            ops_test,
            None,
            "request",
            params,
            app=CLIENT_CHARM,
        )
        if action.status != "completed":
            raise RuntimeError(
                f"{CLIENT_CHARM} request action failed with status {action.status}: "
                f"{action.response}"
            )

        status_code = action.response["status-code"]
        body = action.response["body"]
        if resp_status_code:
            return int(status_code)
        if json_resp:
            return json.loads(body)
        logger.info(f"\n{body}")
        return SimpleNamespace(
            content=body.encode("utf-8"),
            status_code=status_code,
            text=body,
        )

    # fetch the cluster info from the endpoint of this unit
    with requests.Session() as session, tempfile.NamedTemporaryFile(mode="w+") as chain:
        chain.write(admin_secrets["ca-chain"])
        chain.seek(0)

        logger.info(f"Calling: {method} -- {endpoint}")

        request_kwargs = {
            "method": method,
            "url": endpoint,
            "timeout": timeout,
        }
        headers = _http_request_headers(json_resp, extra_headers)

        if headers:
            request_kwargs["headers"] = headers

        if isinstance(payload, str):
            request_kwargs["data"] = payload
        elif isinstance(payload, dict):
            request_kwargs["data"] = json.dumps(payload)

        session.auth = (user, user_password or admin_secrets["password"])

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


async def deploy_opensearch(  # noqa: C901
    ops_test: OpsTest,
    charm: str,
    substrate: str,
    application_name: str,
    num_units: int,
    *,
    series: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
    constraints: Optional[str] = None,
    resources: Optional[Dict[str, str]] = None,
    storage: Optional[Dict[str, Any]] = None,
) -> None:
    """Deploy the OpenSearch charm."""
    deploy_kwargs = {
        "application_name": application_name,
        "num_units": num_units,
    }
    # Juju does not use `series` for K8s applications.
    if series and substrate != "k8s":
        deploy_kwargs["series"] = series
    if config:
        deploy_kwargs["config"] = config
    if constraints:
        deploy_kwargs["constraints"] = constraints
    if resources:
        deploy_kwargs["resources"] = resources
    if storage:
        deploy_kwargs["storage"] = storage
    if substrate == "k8s":
        # This is needed for upgrades
        deploy_kwargs["trust"] = True

    await ops_test.model.deploy(charm, **deploy_kwargs)


def opensearch_client(
    hosts: List[str], user_name: str, password: str, cert_path: str
) -> OpenSearch:
    """Build an opensearch client."""
    return OpenSearch(
        hosts=[{"host": ip, "port": 9200} for ip in hosts],
        http_auth=(user_name, password),
        http_compress=True,
        # Integration tests already pass the current unit IPs explicitly.
        # Node sniffing asks OpenSearch for the full node list and
        # replaces the client's seed hosts with the discovered addresses.
        # The discovered node endpoints are commonly pod IPs or cluster-local DNS names,
        # and the runner outside Kubernetes cannot reliably use them.
        # Disable it here because it is brittle during CA rotation and can fail
        # before the client ever attempts the provided hosts.
        use_ssl=True,  # turn on ssl
        verify_certs=True,  # make sure we verify SSL certificates
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        ca_certs=cert_path,  # cert path on disk
        retry_on_timeout=True,
        max_retries=3,
    )


def get_file_contents(
    ops_test: OpsTest, unit: str, filename: str, substrate: Substrate = "vm"
) -> bytes:
    """Read file contents from a unit."""
    command = ["juju", "ssh", "-m", ops_test.model.name]
    if substrate == "k8s":
        command.extend(["--container", "opensearch", unit, "cat", filename])
    else:
        command.extend([unit, "sudo", "cat", filename])

    return subprocess.check_output(command)


def get_conf_as_dict(
    ops_test: OpsTest, unit: str, filename: str, substrate: Substrate = "vm"
) -> dict[str, str]:
    """Convert a yml config file to a dict."""
    config = get_file_contents(ops_test, unit, filename, substrate)
    return yaml.safe_load(str(config.decode("utf-8")).replace("ll", ""))
