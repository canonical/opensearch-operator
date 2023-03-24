#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from charms.opensearch.v0.helper_cluster import ClusterTopology
from pytest_operator.plugin import OpsTest

from tests.integration.ha.helpers import (
    all_nodes,
    cluster_allocation,
    create_dummy_docs,
    create_dummy_indexes,
    get_number_of_shards_by_node,
    get_shards_by_state,
)
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
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


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="edge", config=config),
        ops_test.model.deploy(my_charm, num_units=1, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME], status="active", timeout=1000
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 1


@pytest.mark.abort_on_fail
async def test_horizontal_scale_up(ops_test: OpsTest) -> None:
    """Tests that new added units to the cluster are discoverable."""
    # scale up
    await ops_test.model.applications[APP_NAME].add_unit(count=2)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=3
    )
    num_units = len(ops_test.model.applications[APP_NAME].units)
    assert num_units == 3

    unit_names = get_application_unit_names(ops_test)
    leader_unit_ip = await get_leader_unit_ip(ops_test)

    assert await check_cluster_formation_successful(ops_test, leader_unit_ip, unit_names)

    shards_by_status = await get_shards_by_state(ops_test, leader_unit_ip)
    assert not shards_by_status.get("INITIALIZING")
    assert not shards_by_status.get("RELOCATING")
    assert not shards_by_status.get("UNASSIGNED")

    # check roles, expecting all nodes to be cm_eligible
    nodes = await all_nodes(ops_test, leader_unit_ip)
    assert ClusterTopology.nodes_count_by_role(nodes)["cluster_manager"] == 3


@pytest.mark.abort_on_fail
async def test_safe_scale_down_shards_realloc(ops_test: OpsTest) -> None:
    """Tests the shutdown of a node, and re-allocation of shards to a newly joined unit.

    The goal of this test is to make sure that shards are automatically relocated after
    a Yellow status on the cluster caused by a scale-down event.
    """
    # scale up
    await ops_test.model.applications[APP_NAME].add_unit(count=1)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=4
    )

    leader_unit_ip = await get_leader_unit_ip(ops_test)
    leader_unit_id = await get_leader_unit_id(ops_test)

    # fetch all nodes
    unit_ids = get_application_unit_ids(ops_test)
    unit_id_to_stop = [unit_id for unit_id in unit_ids if unit_id != leader_unit_id][0]
    unit_ids_to_keep = [unit_id for unit_id in unit_ids if unit_id != unit_id_to_stop]

    # create indices with right num of primary and replica shards, and populate with data
    await create_dummy_indexes(ops_test, leader_unit_ip)
    await create_dummy_docs(ops_test, leader_unit_ip)

    # get initial cluster health - expected to be all good: green
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip)
    assert cluster_health_resp["status"] == "green"
    assert cluster_health_resp["unassigned_shards"] == 0

    # get initial cluster allocation (nodes and their corresponding shards)
    init_shards_per_node = await get_number_of_shards_by_node(ops_test, leader_unit_ip)
    assert init_shards_per_node.get(-1, 0) == 0  # unallocated shards
    print(await cluster_allocation(ops_test, leader_unit_ip))

    # remove the service in the chosen unit
    # TODO getting failures to scale down because removing storage is causing problems.
    await ops_test.model.applications[APP_NAME].destroy_unit(f"{APP_NAME}/{unit_id_to_stop}")
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=3
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
    await ops_test.model.applications[APP_NAME].add_unit(count=1)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_exact_units=4)

    new_unit_id = [
        int(unit.name.split("/")[1])
        for unit in ops_test.model.applications[APP_NAME].units
        if int(unit.name.split("/")[1]) not in unit_ids
    ][0]

    # wait for the new unit to be active
    await ops_test.model.block_until(
        lambda: get_application_unit_status(ops_test)[new_unit_id] == "active"
    )

    # check if the previously unallocated shards have successfully moved to the newest unit
    new_shards_per_node = await get_number_of_shards_by_node(ops_test, leader_unit_ip)
    assert new_shards_per_node[new_unit_id] > 0

    # get new cluster health
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip)
    assert cluster_health_resp["status"] == "green"
    assert cluster_health_resp["unassigned_shards"] == 0
    assert new_shards_per_node.get(-1, 0) == 0


@pytest.mark.abort_on_fail
async def test_safe_scale_down_roles_reassigning(ops_test: OpsTest) -> None:
    """Tests the shutdown of a node with a role requiring the re-balance of the cluster roles.

    The goal of this test is to make sure that roles are automatically recalculated after
    a scale-down event.
    """
    # scale up by 1 unit
    await ops_test.model.applications[APP_NAME].add_unit(count=1)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=5
    )

    leader_unit_ip = await get_leader_unit_ip(ops_test)

    # fetch all nodes
    nodes = await all_nodes(ops_test, leader_unit_ip)
    assert ClusterTopology.nodes_count_by_role(nodes)["cluster_manager"] == 5

    # pick a cluster manager node to remove
    unit_id_to_stop = [
        node.name.split("-")[1]
        for node in nodes
        if node.ip != leader_unit_ip and node.is_cm_eligible()
    ][0]

    # scale-down: remove a cm unit
    await ops_test.model.applications[APP_NAME].destroy_unit(f"{APP_NAME}/{unit_id_to_stop}")
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_exact_units=4)

    # fetch nodes, we expect to have a "cm" node, reconfigured to be "data only" to keep the quorum
    new_nodes = await all_nodes(ops_test, leader_unit_ip)
    assert ClusterTopology.nodes_count_by_role(new_nodes)["cluster_manager"] == 3
    assert ClusterTopology.nodes_count_by_role(new_nodes)["data"] == 4

    # scale-down: remove another cm unit
    unit_id_to_stop = [
        node.name.split("-")[1]
        for node in new_nodes
        if node.ip != leader_unit_ip and node.is_cm_eligible()
    ][0]
    await ops_test.model.applications[APP_NAME].destroy_unit(f"{APP_NAME}/{unit_id_to_stop}")
    # status="blocked"
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_exact_units=3)

    # fetch nodes, we expect to have all nodes "cluster_manager" to keep the quorum
    new_nodes = await all_nodes(ops_test, leader_unit_ip)
    assert ClusterTopology.nodes_count_by_role(new_nodes)["cluster_manager"] == 3
    assert ClusterTopology.nodes_count_by_role(new_nodes)["data"] == 3
