#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import logging
import subprocess
from typing import Dict, List, Optional

import yaml
from charms.opensearch.v0.models import Node
from pytest_operator.plugin import OpsTest
from tenacity import retry, stop_after_attempt, wait_fixed, wait_random

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.helpers import http_request  # get_application_unit_ids_ips,

logger = logging.getLogger(__name__)


class Shard:
    """Class for holding a shard."""

    def __init__(self, index: str, num: int, is_prim: bool, node_id: str, unit_id: int):
        self.index = index
        self.num = num
        self.is_prim = is_prim
        self.node_id = node_id
        self.unit_id = unit_id


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


async def get_elected_cm_unit_id(ops_test: OpsTest, unit_ip: str) -> int:
    """Returns the unit id of the current elected cm node."""
    # get current elected cm node
    cm_node = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cluster/state/cluster_manager_node",
    )
    cm_node_id = cm_node.get("cluster_manager_node")
    if not cm_node_id:
        return -1

    # get all nodes
    all_nodes = await http_request(ops_test, "GET", f"https://{unit_ip}:9200/_nodes")
    return int(all_nodes["nodes"][cm_node_id]["name"].split("-")[1])


async def get_elected_cm_unit(ops_test: OpsTest, unit_ip: str):
    """Returns the current elected cm node unit."""
    cm_id = await get_elected_cm_unit_id(ops_test, unit_ip)
    opensearch_app_name = await app_name(ops_test)
    return ops_test.model.applications[opensearch_app_name].units[cm_id]


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def get_shards_by_state(ops_test: OpsTest, unit_ip: str) -> Dict[str, List[str]]:
    """Returns all shard statuses for all indexes in the cluster.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the OpenSearch unit.

    Returns:
        Whether all indexes have been successfully replicated and shards started.
    """
    response = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/shards",
    )

    indexes_by_status = {}
    for shard in response:
        state = shard["state"]
        if state not in indexes_by_status:
            indexes_by_status[state] = []

        indexes_by_status[state].append(f"{shard['node']}/{shard['index']}")

    return indexes_by_status


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def get_shards_by_index(ops_test: OpsTest, unit_ip: str, index_name: str) -> List[Shard]:
    """Returns the list of shards and their location in cluster for an index.

    Args:
        ops_test: The ops test framework instance.
        unit_ip: The ip of the OpenSearch unit.
        index_name: the name of the index.

    Returns:
        List of shards.
    """
    response = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/{index_name}/_search_shards",
    )

    nodes = response["nodes"]

    result = []
    for shards_collection in response["shards"]:
        for shard in shards_collection:
            unit_id = int(nodes[shard["node"]]["name"].split("-")[1])
            result.append(
                Shard(
                    index=index_name,
                    num=shard["shard"],
                    is_prim=shard["primary"],
                    node_id=shard["node"],
                    unit_id=unit_id,
                )
            )

    return result


async def unit_hostname(ops_test: OpsTest, unit_name: str) -> str:
    """Get hostname for a unit.

    Args:
        ops_test: The ops test object passed into every test case
        unit_name: The name of the unit to be tested

    Returns:
        The machine/container hostname
    """
    _, raw_hostname, _ = await ops_test.juju("ssh", unit_name, "hostname")
    return raw_hostname.strip()


def instance_ip(model: str, instance: str) -> str:
    """Translate juju instance name to IP.

    Args:
        model: The name of the model
        instance: The name of the instance

    Returns:
        The (str) IP address of the instance
    """
    output = subprocess.check_output(f"juju machines --model {model}".split())

    for line in output.decode("utf8").splitlines():
        if instance in line:
            return line.split()[2]


async def get_unit_ip(ops_test: OpsTest, unit_name: str) -> str:
    """Wrapper for getting unit ip.

    Juju incorrectly reports the IP addresses after the network is restored this is reported as a
    bug here: https://github.com/juju/python-libjuju/issues/738 . Once this bug is resolved use of
    `get_unit_ip` should be replaced with `.public_address`

    Args:
        ops_test: The ops test object passed into every test case
        unit_name: The name of the unit to be tested

    Returns:
        The (str) ip of the unit
    """
    return instance_ip(ops_test.model.info.name, await unit_hostname(ops_test, unit_name))


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def cluster_allocation(ops_test: OpsTest, unit_ip: str) -> List[Dict[str, str]]:
    """Fetch the cluster allocation of shards."""
    return await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/allocation",
    )


async def get_number_of_shards_by_node(ops_test: OpsTest, unit_ip: str) -> Dict[int, int]:
    """Get the number of shards allocated per node."""
    init_cluster_alloc = await cluster_allocation(ops_test, unit_ip)

    result = {}
    for alloc in init_cluster_alloc:
        key = -1
        if alloc["node"] != "UNASSIGNED":
            key = int(alloc["node"].split("-")[1])
        result[key] = int(alloc["shards"])

    return result


@retry(
    wait=wait_fixed(wait=5) + wait_random(0, 5),
    stop=stop_after_attempt(15),
)
async def all_nodes(ops_test: OpsTest, unit_ip: str) -> List[Node]:
    """Fetch the cluster allocation of shards."""
    nodes = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/nodes?format=json",
    )
    return [Node(node["name"], node["node.roles"].split(","), node["ip"]) for node in nodes]


async def assert_continuous_writes_consistency(c_writes: ContinuousWrites) -> None:
    """Continuous writes checks."""
    result = await c_writes.stop()

    assert result.max_stored_id == result.count - 1
    assert result.max_stored_id == result.last_expected_id


async def secondary_up_to_date(ops_test: OpsTest, unit_ip, expected_writes) -> bool:
    """Checks if secondary is up to date with the cluster.

    Retries over the period of one minute to give secondary adequate time to copy over data.
    """
    get_secondary_writes = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/series_index",
    )
    logger.error(get_secondary_writes)
    assert get_secondary_writes == expected_writes


def cut_network_from_unit(machine_name: str) -> None:
    """Cut network from a lxc container.

    Args:
        machine_name: lxc container hostname
    """
    # apply a mask (device type `none`)
    cut_network_command = f"lxc config device add {machine_name} eth0 none"
    subprocess.check_call(cut_network_command.split())


def restore_network_for_unit(machine_name: str) -> None:
    """Restore network from a lxc container.

    Args:
        machine_name: lxc container hostname
    """
    # remove mask from eth0
    restore_network_command = f"lxc config device remove {machine_name} eth0"
    subprocess.check_call(restore_network_command.split())


@retry(stop=stop_after_attempt(60), wait=wait_fixed(15))
def wait_network_restore(model_name: str, hostname: str, old_ip: str) -> None:
    """Wait until network is restored.

    Args:
        model_name: The name of the model
        hostname: The name of the instance
        old_ip: old registered IP address
    """
    if instance_ip(model_name, hostname) == old_ip:
        raise Exception("Network not restored, IP address has not changed yet.")


async def get_controller_machine(ops_test: OpsTest) -> str:
    """Return controller machine hostname.

    Args:
        ops_test: The ops test framework instance

    Returns:
        Controller hostname (str)
    """
    _, raw_controller, _ = await ops_test.juju("show-controller")
    controller = yaml.safe_load(raw_controller.strip())
    return [
        machine.get("instance-id")
        for machine in controller[ops_test.controller_name]["controller-machines"].values()
    ][0]


def is_machine_reachable_from(origin_machine: str, target_machine: str) -> bool:
    """Test network reachability between hosts.

    Args:
        origin_machine: hostname of the machine to test connection from
        target_machine: hostname of the machine to test connection to
    """
    try:
        subprocess.check_call(f"lxc exec {origin_machine} -- ping -c 3 {target_machine}".split())
        return True
    except subprocess.CalledProcessError:
        return False


async def send_kill_signal_to_process(
    ops_test: OpsTest, app: str, unit_id: int, signal: str, opensearch_pid: Optional[int] = None
) -> Optional[int]:
    """Run kill with signal in specific unit."""
    unit_name = f"{app}/{unit_id}"

    if opensearch_pid is None:
        get_pid_cmd = f"run --unit {unit_name} -- sudo lsof -ti:9200"
        _, opensearch_pid, _ = await ops_test.juju(*get_pid_cmd.split(), check=True)

    if not opensearch_pid:
        return None

    kill_cmd = f"run --unit {unit_name} -- kill -{signal.upper()} {opensearch_pid}"
    await ops_test.juju(*kill_cmd.split(), check=True)

    return opensearch_pid
