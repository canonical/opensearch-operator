#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time

import pytest
from charms.opensearch.v0.constants_charm import ClusterHealthYellow
from charms.opensearch.v0.helper_cluster import ClusterTopology
from pytest_operator.plugin import OpsTest

from ..ha.helpers import (
    all_nodes,
    assert_continuous_writes_consistency,
    get_elected_cm_unit_id,
    get_number_of_shards_by_node,
    get_shards_by_index,
    get_shards_by_state,
)
from ..helpers import (
    APP_NAME,
    IDLE_PERIOD,
    SERIES,
    app_name,
    check_cluster_formation_successful,
    cluster_health,
    get_application_unit_ids,
    get_application_unit_names,
    get_leader_unit_id,
    get_leader_unit_ip,
    model_conf_with_short_update_schedule,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .continuous_writes import ContinuousWrites
from .helpers_data import create_dummy_docs, create_dummy_indexes, delete_dummy_indexes

logger = logging.getLogger(__name__)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(model_conf_with_short_update_schedule())
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(my_charm, num_units=1, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME], status="active", timeout=1600
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 1


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_horizontal_scale_up(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
) -> None:
    """Tests that new added units to the cluster are discoverable."""
    app = (await app_name(ops_test)) or APP_NAME
    init_units_count = len(ops_test.model.applications[app].units)

    # scale up
    await ops_test.model.applications[app].add_unit(count=2)
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
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


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_safe_scale_down_shards_realloc(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
) -> None:
    """Tests the shutdown of a node, and re-allocation of shards to a newly joined unit.

    The goal of this test is to make sure that shards are automatically relocated after
    a Yellow status on the cluster caused by a scale-down event.
    """
    app = (await app_name(ops_test)) or APP_NAME
    init_units_count = len(ops_test.model.applications[app].units)

    # scale up
    await ops_test.model.applications[app].add_unit(count=1)
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
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
    await wait_until(
        ops_test,
        apps=[app],
        apps_full_statuses={app: {"blocked": [ClusterHealthYellow]}},
        units_statuses=["active"],
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
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=init_units_count + 1,
        idle_period=IDLE_PERIOD,
    )

    new_unit_id = [
        int(unit.name.split("/")[1])
        for unit in ops_test.model.applications[app].units
        if int(unit.name.split("/")[1]) not in unit_ids
    ][0]

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


@pytest.mark.group(1)
async def test_safe_scale_down_remove_leaders(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
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
    await ops_test.model.applications[app].add_unit(count=1)
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=init_units_count + 1,
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    # scale down: remove the juju leader
    leader_unit_id = await get_leader_unit_id(ops_test, app=app)

    await ops_test.model.applications[app].destroy_unit(f"{app}/{leader_unit_id}")
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=init_units_count,
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # scale-down: remove the current elected CM
    first_elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    assert first_elected_cm_unit_id != -1
    await ops_test.model.applications[app].destroy_unit(f"{app}/{first_elected_cm_unit_id}")
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=init_units_count - 1,
        idle_period=IDLE_PERIOD,
        timeout=1800,
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
    time.sleep(IDLE_PERIOD + 60)

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
