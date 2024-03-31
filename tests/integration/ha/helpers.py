#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import subprocess
import time
from typing import Dict, List, Optional

from charms.opensearch.v0.models import Node
from charms.opensearch.v0.opensearch_backups import S3_REPOSITORY
from pytest_operator.plugin import OpsTest
from tenacity import (
    RetryError,
    Retrying,
    retry,
    stop_after_attempt,
    wait_fixed,
    wait_random,
)

from ..helpers import (
    get_application_unit_ids,
    get_application_unit_ids_hostnames,
    get_application_unit_ids_ips,
    get_leader_unit_ip,
    http_request,
    juju_version_major,
    run_action,
)
from .continuous_writes import ContinuousWrites
from .helpers_data import index_docs_count

OPENSEARCH_SERVICE_PATH = "/etc/systemd/system/snap.opensearch.daemon.service"
ORIGINAL_RESTART_DELAY = 20
SECOND_APP_NAME = "second-opensearch"
RESTART_DELAY = 360


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


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
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
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
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

    logger.info(f"Shards:\n{response}")

    indexes_by_status = {}
    for shard in response:
        indexes_by_status.setdefault(shard["state"], []).append(
            f"{shard['node']}/{shard['index']}"
        )

    return indexes_by_status


@retry(
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
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
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
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
    wait=wait_fixed(wait=15) + wait_random(0, 5),
    stop=stop_after_attempt(25),
)
async def all_nodes(ops_test: OpsTest, unit_ip: str) -> List[Node]:
    """Fetch all cluster nodes."""
    response = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_nodes",
    )
    nodes = response.get("nodes", {})

    result = []
    for node_id, node in nodes.items():
        result.append(
            Node(
                name=node["name"],
                roles=node["roles"],
                ip=node["ip"],
                app_name="-".join(node["name"].split("-")[:-1]),
                temperature=node.get("attributes", {}).get("temp"),
            )
        )
    return result


async def assert_continuous_writes_increasing(
    c_writes: ContinuousWrites,
) -> None:
    """Asserts that the continuous writes are increasing."""
    writes_count = await c_writes.count()
    await asyncio.sleep(20)
    more_writes = await c_writes.count()
    assert more_writes > writes_count, "Writes not continuing to DB"


async def assert_continuous_writes_consistency(
    ops_test: OpsTest, c_writes: ContinuousWrites, app: str
) -> None:
    """Continuous writes checks."""
    result = await c_writes.stop()
    logger.info(f"Continuous writes result: {result}")
    assert result.max_stored_id == result.count - 1
    assert result.max_stored_id == result.last_expected_id

    # investigate the data in each shard, primaries and their respective replicas
    units_ips = await get_application_unit_ids_ips(ops_test, app)
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
    ops_test: OpsTest, app: str, unit_id: int, signal: str, opensearch_pid: Optional[int] = None
) -> Optional[int]:
    """Run kill with signal in specific unit."""
    unit_name = f"{app}/{unit_id}"

    bin_cmd = "exec" if juju_version_major() > 2 else "run"
    if opensearch_pid is None:
        get_pid_cmd = f"{bin_cmd} --unit {unit_name} -- sudo lsof -ti:9200"
        _, opensearch_pid, _ = await ops_test.juju(*get_pid_cmd.split(), check=False)

    if not opensearch_pid.strip():
        raise Exception("Could not fetch PID for process listening on port 9200.")

    kill_cmd = f"ssh {unit_name} -- sudo kill -{signal.upper()} {opensearch_pid}"
    return_code, stdout, stderr = await ops_test.juju(*kill_cmd.split(), check=False)
    if return_code != 0:
        raise Exception(f"{kill_cmd} failed -- rc: {return_code} - out: {stdout} - err: {stderr}")

    return opensearch_pid


async def update_restart_delay(ops_test: OpsTest, app: str, unit_id: int, delay: int):
    """Updates the restart delay in the DB service file."""
    unit_name = f"{app}/{unit_id}"

    bin_cmd = "exec" if juju_version_major() > 2 else "run"

    # load the service file from the unit and update it with the new delay
    replace_delay_cmd = (
        f"{bin_cmd} --unit {unit_name} -- "
        f"sudo sed -i -e s/^RestartSec=[0-9]\\+/RestartSec={delay}/g "
        f"{OPENSEARCH_SERVICE_PATH}"
    )
    await ops_test.juju(*replace_delay_cmd.split(), check=True)

    # reload the daemon for systemd to reflect changes
    reload_cmd = f"{bin_cmd} --unit {unit_name} -- sudo systemctl daemon-reload"
    await ops_test.juju(*reload_cmd.split(), check=True)


async def all_processes_down(ops_test: OpsTest, app: str) -> bool:
    """Check if all processes are down."""
    bin_cmd = "exec" if juju_version_major() > 2 else "run"

    for unit_id in get_application_unit_ids(ops_test, app):
        unit_name = f"{app}/{unit_id}"
        get_pid_cmd = f"{bin_cmd} --unit {unit_name} -- sudo lsof -ti:9200"
        _, opensearch_pid, _ = await ops_test.juju(*get_pid_cmd.split(), check=False)
        if opensearch_pid.strip():
            return False

    return True


async def cut_network_from_unit_with_ip_change(ops_test: OpsTest, app: str, unit_id: int) -> None:
    """Cut network from a lxc container, triggering an IP change after restoration."""
    unit_ids_hostnames = await get_application_unit_ids_hostnames(ops_test, app)
    unit_hostname = unit_ids_hostnames[unit_id]

    # apply a mask (device type `none`)
    cut_network_command = f"lxc config device add {unit_hostname} eth0 none"
    subprocess.check_call(cut_network_command.split())

    time.sleep(5)


async def cut_network_from_unit_without_ip_change(
    ops_test: OpsTest, app: str, unit_id: int
) -> None:
    """Cut network from a lxc container (without causing the change of the unit IP address)."""
    unit_ids_hostnames = await get_application_unit_ids_hostnames(ops_test, app)
    unit_hostname = unit_ids_hostnames[unit_id]

    override_command = f"lxc config device override {unit_hostname} eth0"
    try:
        subprocess.check_call(override_command.split())
    except subprocess.CalledProcessError:
        # Ignore if the interface was already overridden.
        pass

    limit_set_command = f"lxc config device set {unit_hostname} eth0 limits.egress=0kbit"
    subprocess.check_call(limit_set_command.split())
    limit_set_command = f"lxc config device set {unit_hostname} eth0 limits.ingress=1kbit"
    subprocess.check_call(limit_set_command.split())
    limit_set_command = f"lxc config set {unit_hostname} limits.network.priority=10"
    subprocess.check_call(limit_set_command.split())

    time.sleep(10)


async def restore_network_for_unit_with_ip_change(unit_hostname: str) -> None:
    """Restore network from a lxc container."""
    # remove mask from eth0
    restore_network_command = f"lxc config device remove {unit_hostname} eth0"
    subprocess.check_call(restore_network_command.split())

    time.sleep(5)


async def restore_network_for_unit_without_ip_change(unit_hostname: str) -> None:
    """Restore network from a lxc container (without causing the change of the unit IP address)."""
    limit_set_command = f"lxc config device set {unit_hostname} eth0 limits.egress="
    subprocess.check_call(limit_set_command.split())
    limit_set_command = f"lxc config device set {unit_hostname} eth0 limits.ingress="
    subprocess.check_call(limit_set_command.split())
    limit_set_command = f"lxc config set {unit_hostname} limits.network.priority="
    subprocess.check_call(limit_set_command.split())

    time.sleep(10)


def is_unit_reachable(from_host: str, to_host: str) -> bool:
    """Test network reachability between hosts."""
    ping = subprocess.call(
        f"lxc exec {from_host} -- ping -c 5 {to_host}".split(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return ping == 0


async def is_network_restored_after_ip_change(
    ops_test: OpsTest, app: str, unit_id: int, unit_ip: str, retries: int = 50
) -> bool:
    try:
        for attempt in Retrying(stop=stop_after_attempt(retries), wait=wait_fixed(wait=30)):
            with attempt:
                logger.error("Network not restored yet, attempting again.")
                units_ips = await get_application_unit_ids_ips(ops_test, app)
                if units_ips[unit_id] == unit_ip:
                    raise Exception

                return True
    except RetryError:
        return False


def storage_app_entries(ops_test: OpsTest, app: str) -> List[str]:
    """Retrieves entries of storage associated with an application.

    Note: this function exists as a temporary solution until this issue is ported to libjuju 2:
    https://github.com/juju/python-libjuju/issues/694
    """
    model_name = ops_test.model.info.name
    proc = subprocess.check_output(f"juju storage --model={model_name}".split())
    proc = proc.decode("utf-8")

    storage_entries = []
    for line in proc.splitlines():
        line = line.strip()
        if not line or "Storage" in line or "detached" in line:
            continue

        unit_name = line.split()[0]
        if unit_name.split("/")[0] == app:
            storage_entries.append(line)

    return storage_entries


def storage_type(ops_test: OpsTest, app: str) -> Optional[str]:
    """Retrieves type of storage associated with an application."""
    storage_entries = storage_app_entries(ops_test, app)
    if not storage_entries:
        return None

    for entry in storage_entries:
        return entry.split()[3]


def storage_id(ops_test: OpsTest, app: str, unit_id: int):
    """Retrieves storage id associated with provided unit."""
    storage_entries = storage_app_entries(ops_test, app)
    if not storage_entries:
        return None

    for entry in storage_entries:
        if entry.split()[0] == f"{app}/{unit_id}":
            return entry.split()[1]


async def print_logs(ops_test: OpsTest, app: str, unit_id: int, msg: str) -> str:
    unit_name = f"{app}/{unit_id}"
    snap_path = "/var/snap/opensearch"

    unicast_hosts = f"ssh {unit_name} -- sudo cat {snap_path}/current/config/unicast_hosts.txt"
    return_code, stdout, stderr = await ops_test.juju(*unicast_hosts.split(), check=False)
    logger.info(f"\n\nUnicast_hosts.txt:\n{stdout}")

    logs = (
        f"ssh {unit_name} -- sudo tail -50 {snap_path}/common/logs/{ops_test.model.info.name}.log"
    )
    return_code, stdout, stderr = await ops_test.juju(*logs.split(), check=False)
    logger.info(f"\n\n\nServer Logs:\n{stdout}")

    return msg


async def wait_for_backup_system_to_settle(ops_test: OpsTest, leader_id: int, unit_ip: str):
    """Waits the backup to finish and move to the finished state or throws a RetryException."""
    for attempt in Retrying(stop=stop_after_attempt(8), wait=wait_fixed(15)):
        with attempt:
            # First, check if current backups are finished
            action = await run_action(
                ops_test, leader_id, "list-backups", params={"output": "json"}
            )
            # Expected format:
            # namespace(status='completed', response={'return-code': 0, 'backups': '{"1": ...}'})
            backups = json.loads(action.response["backups"])
            logger.debug(f"Backups recovered: {backups}")
            if action.status != "completed" or len(backups) == 0:
                raise Exception("Failed to retrieve backup list or list is empty")

            logger.debug(f"list-backups output: {action}")
            # Now, check if we have finished the restore
            indices_status = await http_request(
                ops_test,
                "GET",
                f"https://{unit_ip}:9200/_recovery?human",
            )
            for info in indices_status.values():
                # Now, check the status of each shard
                for shard in info["shards"]:
                    if shard["type"] == "SNAPSHOT" and shard["stage"] != "DONE":
                        raise Exception(f"Recovery failed for shard {shard}")


async def delete_backup(ops_test: OpsTest, backup_id: int) -> None:
    """Deletes a backup."""
    # Now, check if we have finished the restore
    unit_ip = await get_leader_unit_ip(ops_test)
    await http_request(
        ops_test,
        "DELETE",
        f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}/{backup_id}",
    )


async def start_and_check_continuous_writes(ops_test: OpsTest, unit_ip: str, app: str) -> bool:
    """Start continuous writes and check that documents are increasing after some time.

    Given we are restoring an index, we need to make sure ContinuousWrites restart at
    the tip of that index instead of doc_id = 0.

    Closes the writer at the end.
    """
    initial_count = await index_docs_count(ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME)
    logger.info(
        f"Index {ContinuousWrites.INDEX_NAME} has {initial_count} documents, starting there"
    )
    writer = ContinuousWrites(ops_test, app, initial_count=initial_count)
    await writer.start()
    time.sleep(60)
    # Ensure we have writes happening and the index is consistent at the end
    await assert_continuous_writes_increasing(writer)
    await assert_continuous_writes_consistency(ops_test, writer, app)
    # Clear the writer manually, as we are not using the conftest c_writes_runner to do so
    await writer.clear()


async def create_backup(ops_test: OpsTest, leader_id: int, unit_ip: str) -> int:
    """Runs the backup of the cluster."""
    action = await run_action(ops_test, leader_id, "create-backup")
    logger.debug(f"create-backup output: {action}")

    await wait_for_backup_system_to_settle(ops_test, leader_id, unit_ip)
    assert action.status == "completed"
    assert action.response["status"] == "Backup is running."
    return int(action.response["backup-id"])


async def restore(ops_test: OpsTest, backup_id: int, unit_ip: str, leader_id: int) -> bool:
    """Restores a backup."""
    id = backup_id
    if not isinstance(backup_id, int):
        id = int(backup_id)
    action = await run_action(ops_test, leader_id, "restore", params={"backup-id": id})
    logger.debug(f"restore output: {action}")

    await wait_for_backup_system_to_settle(ops_test, leader_id, unit_ip)
    return action.status == "completed"


async def list_backups(ops_test: OpsTest, leader_id: int) -> Dict[str, str]:
    action = await run_action(ops_test, leader_id, "list-backups", params={"output": "json"})
    assert action.status == "completed"
    return json.loads(action.response["backups"])


async def assert_cwrites_backup_consistency(
    ops_test: OpsTest, app: str, leader_id: int, unit_ip: str, backup_id: int, loss: float = 0.4
) -> None:
    """Ensures that continuous writes index has at least the value below.

    assert new_count >= <current-doc-count> * (1 - loss) documents.
    """
    original_count = await index_docs_count(ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME)
    # As stated on: https://discuss.elastic.co/t/how-to-parse-snapshot-dat-file/218888,
    # the only way to discover the documents in a backup is to recover it and check
    # on opensearch.
    # The logic below will run over each backup id, restore it and ensure continuous writes
    # index loss is within the "loss" parameter.
    assert await restore(ops_test, backup_id, unit_ip, leader_id)
    new_count = await index_docs_count(ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME)
    # We expect that new_count has a loss of documents and the numbers are different.
    assert new_count >= int(original_count * (1 - loss)) and new_count < original_count
