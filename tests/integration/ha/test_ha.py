#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
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
from .continuous_writes import ContinuousWrites
from .helpers import (
    all_processes_down,
    app_name,
    assert_continuous_writes_consistency,
    get_elected_cm_unit_id,
    get_shards_by_index,
    send_kill_signal_to_process,
    update_restart_delay,
)
from .helpers_data import create_index, default_doc, delete_index, index_doc, search
from .test_horizontal_scaling import IDLE_PERIOD

logger = logging.getLogger(__name__)


SECOND_APP_NAME = "second-opensearch"
ORIGINAL_RESTART_DELAY = 20
RESTART_DELAY = 360


@pytest.fixture()
async def reset_restart_delay(ops_test: OpsTest):
    """Resets service file delay on all units."""
    yield
    app = (await app_name(ops_test)) or APP_NAME
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, ORIGINAL_RESTART_DELAY)


@pytest.fixture()
async def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    app = (await app_name(ops_test)) or APP_NAME
    return ContinuousWrites(ops_test, app)


@pytest.fixture()
async def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture()
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    await c_writes.start(repl_on_all_nodes=True)
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, self_signed_operator) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    await asyncio.gather(
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    tls = await self_signed_operator
    await ops_test.model.relate(APP_NAME, tls)
    await ops_test.model.wait_for_idle(
        apps=[tls, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_replication_across_members(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
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
    for u_id, u_ip in units.items():
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
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_kill_db_process_node_with_primary_shard(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
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

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    # should also be plenty for the shard primary reelection to happen
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "Writes not continuing to DB"

    # verify that the opensearch service is back running on the old primary unit
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

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_kill_db_process_node_with_elected_cm(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
) -> None:
    """Check cluster can self-heal, data indexed/read when process dies on node with elected CM."""
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

    # Kill the opensearch process
    await send_kill_signal_to_process(ops_test, app, first_elected_cm_unit_id, signal="SIGKILL")

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    # should also be plenty for the cluster manager reelection to happen
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "Writes not continuing to DB"

    # verify that the opensearch service is back running on the old elected cm unit
    assert await is_up(
        ops_test, units_ips[first_elected_cm_unit_id]
    ), "OpenSearch service hasn't restarted."

    # fetch the current elected cluster manager
    current_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    assert (
        current_elected_cm_unit_id != first_elected_cm_unit_id
    ), "Cluster manager election did not happen."

    # verify the node with the old elected cm successfully joined back the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_freeze_db_process_node_with_primary_shard(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
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

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    # should also be plenty for the shard primary reelection to happen
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "writes not continuing to DB"

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
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_freeze_db_process_node_with_elected_cm(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
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

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    # should also be plenty for the cluster manager reelection to happen
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "writes not continuing to DB"

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
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_restart_db_process_node_with_elected_cm(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
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

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    # should also be plenty for the cluster manager reelection to happen
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "writes not continuing to DB"

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

    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_restart_db_process_node_with_primary_shard(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
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

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    # should also be plenty for the cluster manager reelection to happen
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "writes not continuing to DB"

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

    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
async def test_full_cluster_crash(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner, reset_restart_delay
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

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "Writes not continuing to DB"

    # check that cluster health is green (all primary and replica shards allocated)
    health_resp = await cluster_health(ops_test, leader_ip)
    assert health_resp["status"] == "green", f"Cluster {health_resp['status']} - expected green."

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_full_cluster_restart(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner, reset_restart_delay
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

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "Writes not continuing to DB"

    # check that cluster health is green (all primary and replica shards allocated)
    health_resp = await cluster_health(ops_test, leader_ip)
    assert health_resp["status"] == "green", f"Cluster {health_resp['status']} - expected green."

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
