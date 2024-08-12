#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    check_cluster_formation_successful,
    cluster_health,
    get_application_unit_ids,
    get_application_unit_ids_ips,
    get_application_unit_names,
    get_leader_unit_ip,
    get_reachable_unit_ips,
    is_up,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .continuous_writes import ContinuousWrites
from .helpers import (
    ORIGINAL_RESTART_DELAY,
    RESTART_DELAY,
    all_processes_down,
    app_name,
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
    get_elected_cm_unit_id,
    get_shards_by_index,
    send_kill_signal_to_process,
    update_restart_delay,
)
from .helpers_data import create_index, default_doc, delete_index, index_doc, search
from .test_horizontal_scaling import IDLE_PERIOD

logger = logging.getLogger(__name__)


NODE_COUNT_DICT = {
    (node_count): pytest.param(
        node_count,
        id=f"{node_count}",
        marks=[
            pytest.mark.group(f"{node_count}"),
        ],
    )
    for node_count in [2, 3]
}
NODE_COUNT = list(NODE_COUNT_DICT.values())
ONLY_3_NODES = NODE_COUNT_DICT[(3)]


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, node_count: int) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(my_charm, num_units=node_count, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == node_count


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.abort_on_fail
async def test_replication_across_members(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, node_count: int
) -> None:
    """Check consistency, ie write to node, read data from remaining nodes.

    1. Create index with replica shards equal to number of nodes - 1.
    2. Index data.
    3. Query data from all the nodes (all the nodes should contain a copy of the data).
    """
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # create index with r_shards = nodes - 1
    index_name = "test_index"
    await create_index(ops_test, app, leader_unit_ip, index_name, r_shards=len(units) - 1)

    # index document
    doc_id = 12
    await index_doc(ops_test, app, leader_unit_ip, index_name, doc_id)

    # check that the doc can be retrieved from any node
    for u_ip in units.values():
        docs = await search(
            ops_test,
            app,
            u_ip,
            index_name,
            query={"query": {"term": {"_id": doc_id}}},
            preference="_only_local",
        )
        assert len(docs) == 1
        assert docs[0]["_source"] == default_doc(index_name, doc_id)

    await delete_index(ops_test, app, leader_unit_ip, index_name)

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.abort_on_fail
async def test_kill_db_process_node_with_primary_shard(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner, node_count: int
) -> None:
    """Check cluster can self-heal + data indexed/read when process dies on node with P_shard."""
    app = (await app_name(ops_test)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # find unit hosting the primary shard of the index "series-index"
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]

    # Killing the only instance can be disastrous.
    if len(ops_test.model.applications[app].units) < 2:
        old_units_count = len(ops_test.model.applications[app].units)
        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # Kill the opensearch process
    await send_kill_signal_to_process(
        ops_test, app, first_unit_with_primary_shard, signal="SIGKILL"
    )

    if node_count != 2:
        # 2-node clusters do not swap the elected CM automatically
        # One of the nodes must go before that swap happens.
        # This test ensures the cluster can recover and be accessible once again.
        await assert_continuous_writes_increasing(c_writes)

    # verify that the opensearch service is back running on the old primary unit
    assert await is_up(
        ops_test, units_ips[first_unit_with_primary_shard]
    ), "OpenSearch service hasn't restarted."

    # fetch unit hosting the new primary shard of the previous index
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 2

    if node_count != 2:
        # There is no switch of primary shard in 2-node clusters
        for unit_id in units_with_p_shards:
            assert (
                unit_id != first_unit_with_primary_shard
            ), "Primary shard still assigned to the unit where the service was killed."

    # check that the unit previously hosting the primary shard now hosts a replica
    units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
    assert first_unit_with_primary_shard in units_with_r_shards

    # verify the node with the old primary successfully joined the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.abort_on_fail
async def test_kill_db_process_node_with_elected_cm(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner, node_count: int
) -> None:
    """Check cluster can self-heal, data indexed/read when process dies on node with elected CM."""
    app = (await app_name(ops_test)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # find unit currently elected cluster_manager
    first_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)

    # Increase restart delay to give some extra time for the election to happen
    await update_restart_delay(ops_test, app, first_elected_cm_unit_id, 100)

    # Killing the only instance can be disastrous.
    if len(ops_test.model.applications[app].units) < 2:
        old_units_count = len(ops_test.model.applications[app].units)
        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # Kill the opensearch process
    await send_kill_signal_to_process(ops_test, app, first_elected_cm_unit_id, signal="SIGKILL")

    if node_count != 2:
        # This check only makes sense for non 2-node clusters
        # 2-node cluster that loses its elected CM will stop working until that node is back
        await assert_continuous_writes_increasing(c_writes)

    # Return to original configs
    await update_restart_delay(ops_test, app, first_elected_cm_unit_id, ORIGINAL_RESTART_DELAY)

    await asyncio.sleep(100)

    # verify that the opensearch service is back running on the old elected cm unit
    assert await is_up(
        ops_test, units_ips[first_elected_cm_unit_id]
    ), "OpenSearch service hasn't restarted."

    # fetch the current elected cluster manager
    current_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)

    if node_count != 2:
        assert (
            current_elected_cm_unit_id != first_elected_cm_unit_id
        ), "Cluster manager election did not happen."
    else:
        # 2-node clusters do not swap the elected CM automatically
        # One of the nodes must go before that swap happens.
        # This test ensures the cluster can recover and be accessible once again.
        assert (
            current_elected_cm_unit_id == first_elected_cm_unit_id
        ), "Cluster manager election happened unexpectedly."

    # verify the node with the old elected cm successfully joined back the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.abort_on_fail
async def test_freeze_db_process_node_with_primary_shard(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner, node_count: int
) -> None:
    """Check cluster can self-heal + data indexed/read on process freeze on node with P_shard."""
    app = (await app_name(ops_test)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # find unit hosting the primary shard of the index "series-index"
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]

    # Killing the only instance can be disastrous.
    if len(ops_test.model.applications[app].units) < 2:
        old_units_count = len(ops_test.model.applications[app].units)
        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # Freeze the opensearch process
    opensearch_pid = await send_kill_signal_to_process(
        ops_test, app, first_unit_with_primary_shard, signal="SIGSTOP"
    )

    # wait until the SIGSTOP fully takes effect
    time.sleep(10)

    # verify the unit is not reachable
    is_node_up = await is_up(ops_test, units_ips[first_unit_with_primary_shard], retries=3)
    assert not is_node_up

    await assert_continuous_writes_increasing(c_writes)

    # get reachable unit to perform requests against, in case the previously stopped unit
    # is leader unit, so its address is not reachable
    reachable_ip = (await get_reachable_unit_ips(ops_test))[0]

    # fetch unit hosting the new primary shard of the previous index
    shards = await get_shards_by_index(ops_test, reachable_ip, ContinuousWrites.INDEX_NAME)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 2
    for unit_id in units_with_p_shards:
        assert (
            unit_id != first_unit_with_primary_shard
        ), "Primary shard still assigned to the unit where the service was stopped."

    # Un-Freeze the opensearch process in the node previously hosting the primary shard
    await send_kill_signal_to_process(
        ops_test,
        app,
        first_unit_with_primary_shard,
        signal="SIGCONT",
        opensearch_pid=opensearch_pid,
    )

    # verify that the opensearch service is back running on the unit previously hosting the p_shard
    assert await is_up(
        ops_test, units_ips[first_unit_with_primary_shard], retries=3
    ), "OpenSearch service hasn't restarted."

    # fetch unit hosting the new primary shard of the previous index
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)

    # check that the unit previously hosting the primary shard now hosts a replica
    units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
    assert first_unit_with_primary_shard in units_with_r_shards

    # verify the node with the old primary successfully joined back the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.abort_on_fail
async def test_freeze_db_process_node_with_elected_cm(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner, node_count: int
) -> None:
    """Check cluster can self-heal, data indexed/read on process freeze on node with elected CM."""
    app = (await app_name(ops_test)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # find unit currently elected cluster_manager
    first_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)

    # Killing the only instance can be disastrous.
    if len(ops_test.model.applications[app].units) < 2:
        old_units_count = len(ops_test.model.applications[app].units)
        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # Freeze the opensearch process
    opensearch_pid = await send_kill_signal_to_process(
        ops_test, app, first_elected_cm_unit_id, signal="SIGSTOP"
    )

    # wait until the SIGSTOP fully takes effect
    time.sleep(10)

    # verify the unit is not reachable
    is_node_up = await is_up(ops_test, units_ips[first_elected_cm_unit_id], retries=3)
    assert not is_node_up

    if node_count != 2:
        # This check only makes sense for non 2-node clusters
        # 2-node cluster that loses its elected CM will stop working until that node is back
        await assert_continuous_writes_increasing(c_writes)

    # get reachable unit to perform requests against, in case the previously stopped unit
    # is leader unit, so its address is not reachable
    reachable_ip = (await get_reachable_unit_ips(ops_test))[0]

    # fetch the current elected cluster_manager
    current_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, reachable_ip)
    assert (
        current_elected_cm_unit_id != first_elected_cm_unit_id
    ), "Cluster manager still assigned to the unit where the service was stopped."

    # Un-Freeze the opensearch process in the node previously elected CM
    await send_kill_signal_to_process(
        ops_test,
        app,
        first_elected_cm_unit_id,
        signal="SIGCONT",
        opensearch_pid=opensearch_pid,
    )

    # verify that the opensearch service is back running on the unit previously elected CM unit
    assert await is_up(
        ops_test, units_ips[first_elected_cm_unit_id], retries=3
    ), "OpenSearch service hasn't restarted."

    # verify the previously elected CM node successfully joined back the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.abort_on_fail
async def test_restart_db_process_node_with_elected_cm(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner, node_count: int
) -> None:
    """Check cluster self-healing & data indexed/read on process restart on CM node."""
    app = (await app_name(ops_test)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # find unit currently elected cluster manager
    first_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)

    # Killing the only instance can be disastrous.
    if len(ops_test.model.applications[app].units) < 2:
        old_units_count = len(ops_test.model.applications[app].units)
        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # restart the opensearch process
    await send_kill_signal_to_process(ops_test, app, first_elected_cm_unit_id, signal="SIGTERM")

    if node_count != 2:
        # This check only makes sense for non 2-node clusters
        # 2-node cluster that loses its elected CM will stop working until that node is back
        await assert_continuous_writes_increasing(c_writes)

    # verify that the opensearch service is back running on the unit previously elected CM unit
    assert await is_up(
        ops_test, units_ips[first_elected_cm_unit_id]
    ), "OpenSearch service hasn't restarted."

    # fetch the current elected cluster manager
    current_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    assert (
        current_elected_cm_unit_id != first_elected_cm_unit_id
    ), "Cluster manager election did not happen."

    # verify the previously elected CM node successfully joined back the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
    )

    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.abort_on_fail
async def test_restart_db_process_node_with_primary_shard(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner, node_count: int
) -> None:
    """Check cluster can self-heal, data indexed/read on process restart on primary shard node."""
    app = (await app_name(ops_test)) or APP_NAME

    units_ips = await get_application_unit_ids_ips(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # find unit hosting the primary shard of the index "series-index"
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]

    # Killing the only instance can be disastrous.
    if len(ops_test.model.applications[app].units) < 2:
        old_units_count = len(ops_test.model.applications[app].units)
        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units=old_units_count + 1,
            idle_period=IDLE_PERIOD,
        )

    # restart the opensearch process
    await send_kill_signal_to_process(
        ops_test, app, first_unit_with_primary_shard, signal="SIGTERM"
    )

    await assert_continuous_writes_increasing(c_writes)

    # verify that the opensearch service is back running on the previous primary shard unit
    assert await is_up(
        ops_test, units_ips[first_unit_with_primary_shard]
    ), "OpenSearch service hasn't restarted."

    # fetch unit hosting the new primary shard of the previous index
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 2
    for unit_id in units_with_p_shards:
        assert (
            unit_id != first_unit_with_primary_shard
        ), "Primary shard still assigned to the unit where the service was killed."

    # check that the unit previously hosting the primary shard now hosts a replica
    units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
    assert first_unit_with_primary_shard in units_with_r_shards

    # verify the node with the old primary successfully joined the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
    )

    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
async def test_full_cluster_crash(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_balanced_writes_runner,
    reset_restart_delay,
    node_count: int,
) -> None:
    """Check cluster can operate normally after all nodes SIGKILL at same time and come back up."""
    app = (await app_name(ops_test)) or APP_NAME

    leader_ip = await get_leader_unit_ip(ops_test, app)

    # update all units to have a new RESTART_DELAY. Modifying the Restart delay to 3 minutes
    # should ensure enough time for all replicas to be down at the same time.
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, RESTART_DELAY)

    # kill all units simultaneously
    await asyncio.gather(
        *[
            send_kill_signal_to_process(ops_test, app, unit_id, signal="SIGKILL")
            for unit_id in get_application_unit_ids(ops_test, app)
        ]
    )

    # check that all units being down at the same time.
    assert await all_processes_down(ops_test, app), "Not all units down at the same time."

    # Reset restart delay
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, ORIGINAL_RESTART_DELAY)

    # sleep for restart delay + 45 secs max for the election time + node start + cluster formation
    # around 10 sec enough in a good machine - 45 secs for CI
    time.sleep(ORIGINAL_RESTART_DELAY + 45)

    # verify all units are up and running
    for unit_id, unit_ip in (await get_application_unit_ids_ips(ops_test, app)).items():
        assert await is_up(ops_test, unit_ip), f"Unit {unit_id} not restarted after cluster crash."

    # check all nodes successfully joined the same cluster
    assert await check_cluster_formation_successful(
        ops_test, leader_ip, get_application_unit_names(ops_test, app=app)
    )

    await assert_continuous_writes_increasing(c_writes)

    # check that cluster health is green (all primary and replica shards allocated)
    health_resp = await cluster_health(ops_test, leader_ip)
    assert health_resp["status"] == "green", f"Cluster {health_resp['status']} - expected green."

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.parametrize("node_count", NODE_COUNT)
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.abort_on_fail
async def test_full_cluster_restart(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_balanced_writes_runner,
    reset_restart_delay,
    node_count: int,
) -> None:
    """Check cluster can operate normally after all nodes SIGTERM at same time and come back up."""
    app = (await app_name(ops_test)) or APP_NAME

    leader_ip = await get_leader_unit_ip(ops_test, app)

    # update all units to have a new RESTART_DELAY. Modifying the Restart delay to 3 minutes
    # should ensure enough time for all replicas to be down at the same time.
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, RESTART_DELAY)

    # kill all units simultaneously
    await asyncio.gather(
        *[
            send_kill_signal_to_process(ops_test, app, unit_id, signal="SIGTERM")
            for unit_id in get_application_unit_ids(ops_test, app)
        ]
    )

    # check that all units being down at the same time.
    assert await all_processes_down(ops_test, app), "Not all units down at the same time."

    # Reset restart delay
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, ORIGINAL_RESTART_DELAY)

    # sleep for restart delay + 45 secs max for the election time + node start + cluster formation
    # around 10 sec enough in a good machine - 45 secs for CI
    time.sleep(ORIGINAL_RESTART_DELAY + 45)

    # verify all units are up and running
    for unit_id, unit_ip in (await get_application_unit_ids_ips(ops_test, app)).items():
        assert await is_up(ops_test, unit_ip), f"Unit {unit_id} not restarted after cluster crash."

    # check all nodes successfully joined the same cluster
    assert await check_cluster_formation_successful(
        ops_test, leader_ip, get_application_unit_names(ops_test, app=app)
    )

    await assert_continuous_writes_increasing(c_writes)

    # check that cluster health is green (all primary and replica shards allocated)
    health_resp = await cluster_health(ops_test, leader_ip)
    assert health_resp["status"] == "green", f"Cluster {health_resp['status']} - expected green."

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])
