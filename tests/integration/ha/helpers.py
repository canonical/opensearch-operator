#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import subprocess
from typing import Dict, List, Optional

from charms.opensearch.v0.models import Node
from pytest_operator.plugin import OpsTest
from tenacity import (
    RetryError,
    Retrying,
    retry,
    stop_after_attempt,
    wait_fixed,
    wait_random,
)

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.helpers import get_application_unit_ids_ips, http_request

OPENSEARCH_SERVICE_DEFAULT_PATH = "/etc/systemd/system/snap.opensearch.daemon.service"
TMP_SERVICE_PATH = "tests/integration/ha/tmp.service"


class ProcessError(Exception):
    """Raised when a process fails."""


class ProcessRunningError(Exception):
    """Raised when a process is running when it is not expected to be."""


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
    resp = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cluster/state/cluster_manager_node",
    )
    cm_node_id = resp.get("cluster_manager_node")
    if not cm_node_id:
        return -1

    # get all nodes
    resp = await http_request(ops_test, "GET", f"https://{unit_ip}:9200/_nodes")
    return int(resp["nodes"][cm_node_id]["name"].split("-")[1])


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


async def assert_continuous_writes_consistency(
    ops_test: OpsTest, c_writes: ContinuousWrites, app: str
) -> None:
    """Continuous writes checks."""
    result = await c_writes.stop()
    assert result.max_stored_id == result.count - 1
    assert result.max_stored_id == result.last_expected_id

    # investigate the data in each shard, primaries and their respective replicas
    units_ips = get_application_unit_ids_ips(ops_test, app)
    shards = await get_shards_by_index(
        ops_test, list(units_ips.values())[0], ContinuousWrites.INDEX_NAME
    )

    shards_by_id = {}
    for shard in shards:
        shards_by_id.setdefault(shard.num, []).append(shard)

    # count data on each shard. For the continuous writes index, we have 2 primary shards
    # and replica shards of each on all the nodes. In other words: prim1 and its replicas
    # will have a different "num" than prim2 and its replicas.
    count_from_shards = 0
    for shard_num, shards_list in shards_by_id.items():
        count_by_shard = [
            await c_writes.count(
                units_ips[shard.unit_id], preference=f"_shards:{shard_num}|_only_local"
            )
            for shard in shards_list
        ]
        # all shards with the same id must have the same count
        assert len(set(count_by_shard)) == 1
        count_from_shards += count_by_shard[0]

    assert result.count == count_from_shards


async def send_kill_signal_to_process(
    ops_test: OpsTest,
    app: str,
    unit_id: int,
    signal: str,
    opensearch_pid: Optional[int] = None,
) -> Optional[int]:
    """Run kill with signal in specific unit."""
    unit_name = f"{app}/{unit_id}"
    if opensearch_pid is None:
        get_pid_cmd = f"run --unit {unit_name} -- sudo lsof -ti:9200"
        _, opensearch_pid, _ = await ops_test.juju(*get_pid_cmd.split(), check=True)

    if not opensearch_pid:
        raise Exception("Could not fetch PID for process listening on port 9200.")

    kill_cmd = f"ssh {unit_name} -- sudo kill -{signal.upper()} {opensearch_pid}"
    return_code, stdout, stderr = await ops_test.juju(*kill_cmd.split(), check=False)
    if return_code != 0:
        raise Exception(f"{kill_cmd} failed -- rc: {return_code} - out: {stdout} - err: {stderr}")

    return opensearch_pid


async def all_db_processes_down(ops_test: OpsTest) -> bool:
    """Verifies that all units of the charm do not have the DB process running."""
    app = await app_name(ops_test)

    try:
        for attempt in Retrying(stop=stop_after_attempt(60), wait=wait_fixed(3)):
            with attempt:
                for unit in ops_test.model.applications[app].units:
                    search_db_process = f"run --unit {unit.name} pgrep -x mongod"
                    _, processes, _ = await ops_test.juju(*search_db_process.split())
                    # splitting processes by "\n" results in one or more empty lines, hence we
                    # need to process these lines accordingly.
                    processes = [proc for proc in processes.split("\n") if len(proc) > 0]
                    if len(processes) > 0:
                        raise ProcessRunningError
    except RetryError:
        return False

    return True


async def update_restart_delay(ops_test: OpsTest, unit, delay: int):
    """Updates the restart delay in the DB service file.

    When the DB service fails it will now wait for `delay` number of seconds.
    """
    # load the service file from the unit and update it with the new delay
    await unit.scp_from(source=OPENSEARCH_SERVICE_DEFAULT_PATH, destination=TMP_SERVICE_PATH)
    with open(TMP_SERVICE_PATH, "r") as opensearch_service_file:
        opensearch_service = opensearch_service_file.readlines()

    for index, line in enumerate(opensearch_service):
        if "RestartSec" in line:
            opensearch_service[index] = f"RestartSec={delay}s\n"

    with open(TMP_SERVICE_PATH, "w") as service_file:
        service_file.writelines(opensearch_service)

    # Upload the changed file back to the unit. We cannot scp this file directly to
    # OPENSEARCH_SERVICE_DEFAULT_PATH since this directory has strict permissions, so we scp it
    # elsewhere and then move it to OPENSEARCH_SERVICE_DEFAULT_PATH.
    await unit.scp_to(source=TMP_SERVICE_PATH, destination="opensearch.service")
    mv_cmd = f"run --unit {unit.name} mv /home/ubuntu/opensearch.service {OPENSEARCH_SERVICE_DEFAULT_PATH}"
    return_code, _, _ = await ops_test.juju(*mv_cmd.split())
    if return_code != 0:
        raise ProcessError(f"Command: {mv_cmd} failed on unit: {unit.name}.")

    # remove tmp file from machine
    subprocess.call(["rm", TMP_SERVICE_PATH])

    # reload the daemon for systemd otherwise changes are not saved
    reload_cmd = f"run --unit {unit.name} systemctl daemon-reload"
    return_code, _, _ = await ops_test.juju(*reload_cmd.split())
    if return_code != 0:
        raise ProcessError(f"Command: {reload_cmd} failed on unit: {unit.name}.")
