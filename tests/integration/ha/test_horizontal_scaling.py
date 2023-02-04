#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.helpers import (
    create_dummy_docs,
    create_dummy_indexes,
    get_number_of_shards_by_node,
    get_shards_by_state,
)
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    check_cluster_formation_successful,
    cluster_health,
    get_application_unit_names,
    get_application_unit_status,
    get_leader_unit_id,
    get_leader_unit_ip,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


@pytest.mark.ha_tests
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        my_charm,
        num_units=1,
        series=SERIES,
    )
    await ops_test.model.wait_for_idle()

    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=1000)
    assert len(ops_test.model.applications[APP_NAME].units) == 1

    # Deploy TLS Certificates operator.
    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="edge", config=config)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME], status="active", timeout=1000
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=1
    )


@pytest.mark.ha_tests
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


@pytest.mark.ha_tests
@pytest.mark.abort_on_fail
async def test_safe_scale_down_shards_realloc(ops_test: OpsTest) -> None:
    """Tests the shutdown of a node, and re-allocation of shards to a newly joined unit.

    The goal of this test is to make sure that shards are automatically relocated after
    a Yellow status on the cluster caused by a scale-down event.
    """
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    leader_unit_id = await get_leader_unit_id(ops_test)
    unit_id_to_stop = [unit_id for unit_id in UNIT_IDS if unit_id != leader_unit_id][0]
    unit_ids_to_keep = [unit_id for unit_id in UNIT_IDS if unit_id != unit_id_to_stop]

    # create indices with right num of primary and replica shards, and populate with data
    await create_dummy_indexes(ops_test, leader_unit_ip)
    await create_dummy_docs(ops_test, leader_unit_ip)

    # get initial cluster health - expected to be all good: green
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip)
    assert cluster_health_resp["status"] == "green"
    assert cluster_health_resp["unassigned_shards"] == 0

    # get initial cluster allocation (nodes and their corresponding shards)
    init_shards_per_node = await get_number_of_shards_by_node(ops_test, leader_unit_ip)

    # remove the service in the chosen unit
    # await run_action(ops_test, unit_id_to_stop, "stop-service")
    await ops_test.model.applications[APP_NAME].destroy_unit(f"{APP_NAME}/{unit_id_to_stop}")
    # await ops_test.model.applications[APP_NAME].add_unit(count=-1)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=2
    )

    # check if at least partial shard re-allocation happened
    new_shards_per_node = await get_number_of_shards_by_node(ops_test, leader_unit_ip)

    # some shards should have been reallocated, not all due to already existing replicas elsewhere
    assert new_shards_per_node.get(unit_id_to_stop, 0) < init_shards_per_node[unit_id_to_stop]

    are_some_shards_reallocated = False
    for unit_id in unit_ids_to_keep:
        are_some_shards_reallocated = (
            are_some_shards_reallocated
            or new_shards_per_node[unit_id] > init_shards_per_node[unit_id]
        )
    assert are_some_shards_reallocated

    # get new cluster health
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip)

    # not all shards should have been reallocated
    assert new_shards_per_node.get(unit_id_to_stop, 0) > 0
    assert cluster_health_resp["status"] == "yellow"

    # scale up by 1 unit
    await ops_test.model.applications[APP_NAME].add_unit(count=1)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_exact_units=3)

    new_unit_id = [
        int(unit.name.split("/")[1])
        for unit in ops_test.model.applications[APP_NAME].units
        if int(unit.name.split("/")[1]) not in UNIT_IDS
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
