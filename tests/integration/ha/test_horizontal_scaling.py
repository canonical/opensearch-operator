#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time

import pytest
from charms.opensearch.v0.helper_cluster import ClusterTopology
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    all_nodes,
    assert_continuous_writes_consistency,
    get_elected_cm_unit_id,
    get_number_of_shards_by_node,
    get_shards_by_index,
    get_shards_by_state,
)
from tests.integration.ha.helpers_data import (
    create_dummy_docs,
    create_dummy_indexes,
    delete_dummy_indexes,
)
from tests.integration.helpers import (
    APP_NAME,
    IDLE_PERIOD,
    MODEL_CONFIG,
    SERIES,
    app_name,
    check_cluster_formation_successful,
    cluster_health,
    get_application_unit_ids,
    get_application_unit_names,
    get_application_unit_status,
    get_leader_unit_id,
    get_leader_unit_ip,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


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
    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(my_charm, num_units=1, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME], status="active", timeout=1600
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 1


@pytest.mark.abort_on_fail
async def test_horizontal_scale_up(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Tests that new added units to the cluster are discoverable."""
    app = (await app_name(ops_test)) or APP_NAME
    init_units_count = len(ops_test.model.applications[app].units)

    # scale up
    await ops_test.model.applications[app].add_unit(count=2)
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=init_units_count + 2,
        idle_period=IDLE_PERIOD,
    )
    num_units = len(ops_test.model.applications[app].units)
    assert num_units == init_units_count + 2

    unit_names = get_application_unit_names(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    assert await check_cluster_formation_successful(ops_test, leader_unit_ip, unit_names)

    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip)
    assert cluster_health_resp["status"] == "green"

    shards_by_status = await get_shards_by_state(ops_test, leader_unit_ip)
    assert not shards_by_status.get("INITIALIZING")
    assert not shards_by_status.get("RELOCATING")
    assert not shards_by_status.get("UNASSIGNED")

    # check roles, expecting all nodes to be cm_eligible
    nodes = await all_nodes(ops_test, leader_unit_ip)
    num_units = len(ops_test.model.applications[app].units)
    assert (
        ClusterTopology.nodes_count_by_role(nodes)["cluster_manager"] == num_units
        if num_units % 2 != 0
        else num_units - 1
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.abort_on_fail
async def test_safe_scale_down_shards_realloc(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Tests the shutdown of a node, and re-allocation of shards to a newly joined unit.

    The goal of this test is to make sure that shards are automatically relocated after
    a Yellow status on the cluster caused by a scale-down event.
    """
    app = (await app_name(ops_test)) or APP_NAME
    init_units_count = len(ops_test.model.applications[app].units)

    # scale up
    await ops_test.model.applications[app].add_unit(count=1)
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=init_units_count + 1,
        idle_period=IDLE_PERIOD,
    )

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    leader_unit_id = await get_leader_unit_id(ops_test, app=app)

    # fetch all nodes
    unit_ids = get_application_unit_ids(ops_test, app=app)
    unit_id_to_stop = [unit_id for unit_id in unit_ids if unit_id != leader_unit_id][0]
    unit_ids_to_keep = [unit_id for unit_id in unit_ids if unit_id != unit_id_to_stop]

    # create indices with right num of primary and replica shards, and populate with data
    await create_dummy_indexes(ops_test, app, leader_unit_ip, max_r_shards=init_units_count)
    await create_dummy_docs(ops_test, app, leader_unit_ip)

    # get initial cluster health - expected to be all good: green
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip, wait_for_green_first=True)
    assert cluster_health_resp["status"] == "green"
    assert cluster_health_resp["unassigned_shards"] == 0

    # get initial cluster allocation (nodes and their corresponding shards)
    init_shards_per_node = await get_number_of_shards_by_node(ops_test, leader_unit_ip)
    assert init_shards_per_node.get(-1, 0) == 0  # unallocated shards

    # remove the service in the chosen unit
    await ops_test.model.applications[app].destroy_unit(f"{app}/{unit_id_to_stop}")
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=init_units_count,
        idle_period=IDLE_PERIOD,
    )

    # check if at least partial shard re-allocation happened
    new_shards_per_node = await get_number_of_shards_by_node(ops_test, leader_unit_ip)

    # some shards should have been reallocated, NOT ALL due to already existing replicas elsewhere
    assert new_shards_per_node.get(-1, 0) > 0  # some shards not reallocated

    are_some_shards_reallocated = False
    for unit_id in unit_ids_to_keep:
        are_some_shards_reallocated = (
            are_some_shards_reallocated
            or new_shards_per_node[unit_id] > init_shards_per_node[unit_id]
        )
    assert are_some_shards_reallocated

    # get new cluster health
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip)

    # not all replica shards should have been reallocated
    assert cluster_health_resp["status"] == "yellow"

    # scale up by 1 unit
    await ops_test.model.applications[app].add_unit(count=1)
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=init_units_count + 1,
        idle_period=IDLE_PERIOD,
    )

    new_unit_id = [
        int(unit.name.split("/")[1])
        for unit in ops_test.model.applications[app].units
        if int(unit.name.split("/")[1]) not in unit_ids
    ][0]

    # wait for the new unit to be active
    await ops_test.model.block_until(
        lambda: get_application_unit_status(ops_test, app=app)[new_unit_id] == "active"
    )

    # check if the previously unallocated shards have successfully moved to the newest unit
    new_shards_per_node = await get_number_of_shards_by_node(ops_test, leader_unit_ip)
    assert new_shards_per_node[new_unit_id] > 0

    # get new cluster health
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip)
    assert cluster_health_resp["status"] == "green"
    assert cluster_health_resp["unassigned_shards"] == 0
    assert new_shards_per_node.get(-1, 0) == 0

    # delete the dummy indexes
    await delete_dummy_indexes(ops_test, app, leader_unit_ip)

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.abort_on_fail
async def test_safe_scale_down_roles_reassigning(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Tests the shutdown of a node with a role requiring the re-balance of the cluster roles.

    The goal of this test is to make sure that roles are automatically recalculated after
    a scale-up/down event. For this end, we want to start testing with an even number of units.
    """
    app = (await app_name(ops_test)) or APP_NAME
    init_units_count = len(ops_test.model.applications[app].units)

    # scale up by 1/2 units depending on the parity of current units: to trigger roles reassignment
    if init_units_count % 2 == 1:
        # this will NOT trigger any role reassignment, but will ensure the next call will
        await ops_test.model.applications[app].add_unit(count=1)
        await ops_test.model.wait_for_idle(
            apps=[app],
            status="active",
            timeout=1000,
            wait_for_exact_units=init_units_count + 1,
            idle_period=IDLE_PERIOD,
        )
        init_units_count += 1

    # going from an even to odd number of units, this should trigger a role reassignment
    await ops_test.model.applications[app].add_unit(count=1)
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=init_units_count + 1,
        idle_period=IDLE_PERIOD,
    )

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # fetch all nodes
    nodes = await all_nodes(ops_test, leader_unit_ip)
    num_units = len(ops_test.model.applications[app].units)
    assert ClusterTopology.nodes_count_by_role(nodes)["cluster_manager"] == num_units

    # pick a cluster manager node to remove
    unit_id_to_stop = [
        node.name.split("-")[1]
        for node in nodes
        if node.ip != leader_unit_ip and node.is_cm_eligible()
    ][0]

    # scale-down: remove a cm unit
    await ops_test.model.applications[app].destroy_unit(f"{app}/{unit_id_to_stop}")
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=init_units_count,
        idle_period=IDLE_PERIOD,
    )

    # we expect to have a "cm" node, reconfigured to be "data only" to keep the quorum
    new_nodes = await all_nodes(ops_test, leader_unit_ip)
    num_units = len(ops_test.model.applications[app].units)
    assert ClusterTopology.nodes_count_by_role(new_nodes)["cluster_manager"] == num_units - 1
    assert ClusterTopology.nodes_count_by_role(new_nodes)["data"] == num_units

    # scale-down: remove another cm unit
    unit_id_to_stop = [
        node.name.split("-")[1]
        for node in new_nodes
        if node.ip != leader_unit_ip and node.is_cm_eligible()
    ][0]
    await ops_test.model.applications[app].destroy_unit(f"{app}/{unit_id_to_stop}")
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=num_units - 1,
        idle_period=IDLE_PERIOD,
    )

    # fetch nodes, we expect to have all nodes "cluster_manager" to keep the quorum
    new_nodes = await all_nodes(ops_test, leader_unit_ip)
    num_units = len(ops_test.model.applications[app].units)
    assert ClusterTopology.nodes_count_by_role(new_nodes)["cluster_manager"] == num_units
    assert ClusterTopology.nodes_count_by_role(new_nodes)["data"] == num_units

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


async def test_safe_scale_down_remove_leaders(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Tests the removal of specific units (elected cm, juju leader, node with prim shard).

    The goal of this test is to make sure that:
     - the CM reelection happens successfully.
     - the leader-elected event gets triggered successfully and
        leadership related events on the charm work correctly, i.e: roles reassigning.
     - the primary shards reelection happens successfully.
    It is worth noting that we're going into this test with an odd number of units.
    """
    app = (await app_name(ops_test)) or APP_NAME
    init_units_count = len(ops_test.model.applications[app].units)

    # scale up by 2 units
    await ops_test.model.applications[app].add_unit(count=2)
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=init_units_count + 2,
        idle_period=IDLE_PERIOD,
    )

    # scale down: remove the juju leader
    leader_unit_id = await get_leader_unit_id(ops_test, app=app)

    await ops_test.model.applications[app].destroy_unit(f"{app}/{leader_unit_id}")
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=init_units_count + 1,
        idle_period=IDLE_PERIOD,
    )

    # make sure the duties supposed to be done by the departing leader are done
    # we expect to have 3 cm-eligible+data (one of which will be elected) and
    # 1 data-only nodes as per the roles-reassigning logic
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    nodes = await all_nodes(ops_test, leader_unit_ip)
    assert (
        ClusterTopology.nodes_count_by_role(nodes)["cluster_manager"] == init_units_count + 1
        if init_units_count % 2 == 0
        else init_units_count + 2
    )
    assert ClusterTopology.nodes_count_by_role(nodes)["data"] == init_units_count + 2

    # scale-down: remove the current elected CM
    first_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    assert first_elected_cm_unit_id != -1
    await ops_test.model.applications[app].destroy_unit(f"{app}/{first_elected_cm_unit_id}")
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=init_units_count,
        idle_period=IDLE_PERIOD,
    )

    # check if CM re-election happened
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    second_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    assert second_elected_cm_unit_id != -1
    assert second_elected_cm_unit_id != first_elected_cm_unit_id

    # check health of cluster
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip, wait_for_green_first=True)
    assert cluster_health_resp["status"] == "green"

    # remove node containing primary shard of index "series_index"
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]
    await ops_test.model.applications[app].destroy_unit(f"{app}/{unit_with_primary_shard}")

    # sleep for a couple of minutes for the model to stabilise
    time.sleep(IDLE_PERIOD)

    writes = await c_writes.count()

    # check that the primary shard reelection happened
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
    assert len(units_with_p_shards) == 1

    for unit_id in units_with_p_shards:
        assert (
            unit_id != unit_with_primary_shard
        ), "Primary shard still assigned to destroyed unit."

    # check that writes are still going after the removal / p_shard reelection
    time.sleep(3)
    new_writes = await c_writes.count()
    assert new_writes > writes

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
