#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    app_name,
    assert_continuous_writes_consistency,
    cut_network_from_unit_with_ip_change,
    cut_network_from_unit_without_ip_change,
    get_elected_cm_unit_id,
    get_shards_by_index,
    is_network_restored_after_ip_change,
    is_unit_reachable,
    restore_network_for_unit_with_ip_change,
    restore_network_for_unit_without_ip_change,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    check_cluster_formation_successful,
    get_application_unit_ids_hostnames,
    get_application_unit_ids_ips,
    get_application_unit_names,
    get_controller_hostname,
    get_leader_unit_ip,
    is_up,
)
from tests.integration.helpers_deployments import wait_until
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


@pytest.fixture()
async def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    app = (await app_name(ops_test)) or APP_NAME
    return ContinuousWrites(ops_test, app)


@pytest.fixture()
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    await c_writes.start(repl_on_all_nodes=True)
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
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
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.abort_on_fail
async def test_full_network_cut_with_ip_change_node_with_elected_cm(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
) -> None:
    """Check that cluster can self-heal and unit reconfigures itself with new IP."""
    app = (await app_name(ops_test)) or APP_NAME

    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)
    unit_ids_hostnames = await get_application_unit_ids_hostnames(ops_test, app)

    # find unit currently elected cluster_manager
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    first_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    first_elected_cm_unit_hostname = unit_ids_hostnames[first_elected_cm_unit_id]
    first_elected_cm_unit_ip = unit_ids_ips[first_elected_cm_unit_id]

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

    # verify the node is well reachable
    assert await is_up(
        ops_test, first_elected_cm_unit_ip
    ), "Initial elected cluster manager node not online."

    # cut network from current elected cm unit
    await cut_network_from_unit_with_ip_change(ops_test, app, first_elected_cm_unit_id)

    logger.info(f"Network cut from unit: {first_elected_cm_unit_id}")

    # verify machine not reachable from / to peer units
    for unit_id, unit_hostname in unit_ids_hostnames.items():
        if unit_id != first_elected_cm_unit_id:
            assert not is_unit_reachable(
                from_host=unit_hostname, to_host=first_elected_cm_unit_hostname
            ), "Unit is still reachable from other units."
            assert not is_unit_reachable(
                from_host=first_elected_cm_unit_hostname, to_host=unit_hostname
            ), "Unit can still reach other units."

    # check reach from controller - noticed that the controller is able to ping the unit for longer
    assert not is_unit_reachable(
        from_host=await get_controller_hostname(ops_test), to_host=first_elected_cm_unit_hostname
    ), "Unit is still reachable from controller"

    # verify node not up anymore
    assert not await is_up(
        ops_test, first_elected_cm_unit_ip, retries=3
    ), "Connection still possible to the first CM node where the network was cut."

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "Writes not continuing to DB"

    # check new CM got elected
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    current_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    assert current_elected_cm_unit_id != first_elected_cm_unit_id, "No CM re-election happened."

    # restore the network on the unit
    await restore_network_for_unit_with_ip_change(first_elected_cm_unit_hostname)

    # Wait until the cluster becomes idle (new TLS certs, node reconfigured / restarted).
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(unit_ids_ips),
        idle_period=IDLE_PERIOD,
        timeout=2400,
    )

    # check unit network restored
    assert await is_network_restored_after_ip_change(
        ops_test, app, first_elected_cm_unit_id, first_elected_cm_unit_ip
    ), "Network could not be restored."

    # fetch the new IPs
    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)
    first_cm_unit_new_ip = unit_ids_ips[first_elected_cm_unit_id]

    # check if node up and is included in the cluster formation
    assert await is_up(ops_test, first_cm_unit_new_ip), "Unit still not up."

    # verify the previously elected CM node successfully joined the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, first_cm_unit_new_ip, get_application_unit_names(ops_test, app)
    ), "Unit did NOT join the rest of the cluster."

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.abort_on_fail
async def test_full_network_cut_with_ip_change_node_with_primary_shard(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
) -> None:
    """Check that cluster can self-heal and unit reconfigures itself with new IP."""
    app = (await app_name(ops_test)) or APP_NAME

    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)
    unit_ids_hostnames = await get_application_unit_ids_hostnames(ops_test, app)

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # find unit hosting the primary shard of the index "series-index"
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]
    first_unit_with_primary_shard_hostname = unit_ids_hostnames[first_unit_with_primary_shard]
    first_unit_with_primary_shard_ip = unit_ids_ips[first_unit_with_primary_shard]

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

    # verify the node is well reachable
    assert await is_up(
        ops_test, first_unit_with_primary_shard_ip
    ), "Initial node with primary shard of 'series_index' elected cluster manager node not online."

    # cut network from current elected cm unit
    await cut_network_from_unit_with_ip_change(ops_test, app, first_unit_with_primary_shard)

    # verify machine not reachable from / to peer units
    for unit_id, unit_hostname in unit_ids_hostnames.items():
        if unit_id != first_unit_with_primary_shard:
            assert not is_unit_reachable(
                from_host=unit_hostname, to_host=first_unit_with_primary_shard_hostname
            ), "Unit is still reachable from other units."
            assert not is_unit_reachable(
                from_host=first_unit_with_primary_shard_hostname, to_host=unit_hostname
            ), "Unit can still reach other units."

    # check reach from controller - noticed that the controller is able to ping the unit for longer
    assert not is_unit_reachable(
        from_host=await get_controller_hostname(ops_test),
        to_host=first_unit_with_primary_shard_hostname,
    ), "Unit is still reachable from controller"

    # verify node not up anymore
    assert not await is_up(
        ops_test, first_unit_with_primary_shard_ip, retries=3
    ), "Connection still possible to the first unit with primary shard where the network was cut."

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "Writes not continuing to DB"

    # check new primary shard got elected
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # fetch units hosting the new primary shards of the previous index
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 2
    for unit_id in units_with_p_shards:
        assert (
            unit_id != first_unit_with_primary_shard
        ), "Primary shard still assigned to the unit where the service was killed."

    # restore the network on the unit
    await restore_network_for_unit_with_ip_change(first_unit_with_primary_shard_hostname)

    # Wait until the cluster becomes idle (new TLS certs, node reconfigured / restarted).
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(unit_ids_ips),
        idle_period=IDLE_PERIOD,
        timeout=2400,
    )

    # check unit network restored
    assert await is_network_restored_after_ip_change(
        ops_test, app, first_unit_with_primary_shard, first_unit_with_primary_shard_ip
    ), "Network could not be restored."

    # Fetch the new IPs
    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)
    first_unit_with_primary_shard_new_ip = unit_ids_ips[first_unit_with_primary_shard]

    # check if node up and is included in the cluster formation
    assert await is_up(ops_test, first_unit_with_primary_shard_new_ip), "Unit still not up."

    # get new leader unit ip
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # check that the unit previously hosting the primary shard now hosts a replica
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
    assert first_unit_with_primary_shard in units_with_r_shards

    # verify the node with the old primary successfully joined the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, first_unit_with_primary_shard_new_ip, get_application_unit_names(ops_test, app)
    ), "Unit did NOT join the rest of the cluster."

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.abort_on_fail
async def test_full_network_cut_without_ip_change_node_with_elected_cm(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
) -> None:
    """Check that cluster can self-heal and unit reconfigures itself with network cut.."""
    app = (await app_name(ops_test)) or APP_NAME

    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)
    unit_ids_hostnames = await get_application_unit_ids_hostnames(ops_test, app)

    # find unit currently elected cluster_manager
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    first_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    first_elected_cm_unit_ip = unit_ids_ips[first_elected_cm_unit_id]
    first_elected_cm_unit_hostname = unit_ids_hostnames[first_elected_cm_unit_id]

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

    # verify the node is well reachable
    assert await is_up(
        ops_test, first_elected_cm_unit_ip
    ), "Initial elected cluster manager node not online."

    # cut network from current elected cm unit
    await cut_network_from_unit_without_ip_change(ops_test, app, first_elected_cm_unit_id)

    # verify machine not reachable from / to peer units
    for unit_id, unit_hostname in unit_ids_hostnames.items():
        if unit_id != first_elected_cm_unit_id:
            assert not is_unit_reachable(
                from_host=unit_hostname, to_host=first_elected_cm_unit_hostname
            ), "Unit is still reachable from other units."

    # check reach from controller - noticed that the controller is able to ping the unit for longer
    assert not is_unit_reachable(
        from_host=await get_controller_hostname(ops_test), to_host=first_elected_cm_unit_hostname
    ), "Unit is still reachable from controller"

    # verify node not up anymore
    assert not await is_up(
        ops_test, first_elected_cm_unit_ip, retries=3
    ), "Connection still possible to the first CM node where the network was cut."

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "Writes not continuing to DB"

    # check new CM got elected
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    current_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    assert current_elected_cm_unit_id != first_elected_cm_unit_id, "No CM re-election happened."

    # restore the network on the unit
    await restore_network_for_unit_without_ip_change(first_elected_cm_unit_hostname)

    # Wait until the cluster becomes idle (new TLS certs, node reconfigured / restarted).
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(unit_ids_ips),
        idle_period=IDLE_PERIOD,
        timeout=2000,
    )

    # check if node up and is included in the cluster formation
    assert await is_up(ops_test, first_elected_cm_unit_ip), "Unit still not up."

    # verify the previously elected CM node successfully joined the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, first_elected_cm_unit_ip, get_application_unit_names(ops_test, app)
    ), "Unit did NOT join the rest of the cluster."

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.abort_on_fail
async def test_full_network_cut_without_ip_change_node_with_primary_shard(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
) -> None:
    """Check that cluster can self-heal and unit reconfigures itself with network cut."""
    app = (await app_name(ops_test)) or APP_NAME

    unit_ids_ips = await get_application_unit_ids_ips(ops_test, app)
    unit_ids_hostnames = await get_application_unit_ids_hostnames(ops_test, app)

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # find unit hosting the primary shard of the index "series-index"
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]
    first_unit_with_primary_shard_hostname = unit_ids_hostnames[first_unit_with_primary_shard]
    first_unit_with_primary_shard_ip = unit_ids_ips[first_unit_with_primary_shard]

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

    # verify the node is well reachable
    assert await is_up(
        ops_test, first_unit_with_primary_shard_ip
    ), "Initial node with primary shard of 'series_index' elected cluster manager node not online."

    # cut network from current elected cm unit
    await cut_network_from_unit_without_ip_change(ops_test, app, first_unit_with_primary_shard)

    # verify machine not reachable from / to peer units
    for unit_id, unit_hostname in unit_ids_hostnames.items():
        if unit_id != first_unit_with_primary_shard:
            assert not is_unit_reachable(
                from_host=unit_hostname, to_host=first_unit_with_primary_shard_hostname
            ), "Unit is still reachable from other units."

    # check reach from controller - noticed that the controller is able to ping the unit for longer
    assert not is_unit_reachable(
        from_host=await get_controller_hostname(ops_test),
        to_host=first_unit_with_primary_shard_hostname,
    ), "Unit is still reachable from controller"

    # verify node not up anymore
    assert not await is_up(
        ops_test, first_unit_with_primary_shard_ip, retries=3
    ), "Connection still possible to the first unit with primary shard where the network was cut."

    # verify new writes are continuing by counting the number of writes before and after 5 seconds
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "Writes not continuing to DB"

    # check new primary shard got elected
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # fetch units hosting the new primary shards of the previous index
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 2
    for unit_id in units_with_p_shards:
        assert (
            unit_id != first_unit_with_primary_shard
        ), "Primary shard still assigned to the unit where the service was killed."

    # restore the network on the unit
    await restore_network_for_unit_without_ip_change(first_unit_with_primary_shard_hostname)

    # Wait until the cluster becomes idle (new TLS certs, node reconfigured / restarted).
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(unit_ids_ips),
        idle_period=IDLE_PERIOD,
        timeout=2000,
    )

    # check if node up and is included in the cluster formation
    assert await is_up(ops_test, first_unit_with_primary_shard_ip), "Unit still not up."

    # check that the unit previously hosting the primary shard now hosts a replica
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
    assert first_unit_with_primary_shard in units_with_r_shards

    # verify the node with the old primary successfully joined the rest of the fleet
    assert await check_cluster_formation_successful(
        ops_test, first_unit_with_primary_shard_ip, get_application_unit_names(ops_test, app)
    ), "Unit did NOT join the rest of the cluster."

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
