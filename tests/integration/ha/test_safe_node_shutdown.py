#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.helpers import (
    create_dummy_docs,
    create_dummy_indexes,
    get_number_of_shards_by_node,
)
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    cluster_health,
    get_application_unit_status,
    get_leader_unit_id,
    get_leader_unit_ip,
    run_action,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


@pytest.mark.ha_service_tests
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        my_charm,
        num_units=len(UNIT_IDS),
        series=SERIES,
    )
    await ops_test.model.wait_for_idle()

    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=1000)
    assert len(ops_test.model.applications[APP_NAME].units) == len(UNIT_IDS)

    # Deploy TLS Certificates operator.
    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="edge", config=config)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME], status="active", timeout=1000
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=len(UNIT_IDS)
    )


@pytest.mark.ha_service_tests
@pytest.mark.abort_on_fail
async def test_safe_node_shutdown(ops_test: OpsTest) -> None:
    """Tests the shutdown of a node, and re-allocation of shards to a newly joined unit."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    leader_unit_id = await get_leader_unit_id(ops_test)
    unit_id_to_stop = [unit_id for unit_id in UNIT_IDS if unit_id != leader_unit_id][0]
    unit_ids_to_keep = [unit_id for unit_id in UNIT_IDS if unit_id != unit_id_to_stop]

    # create indices and populate with data
    await create_dummy_indexes(ops_test, leader_unit_ip)
    await create_dummy_docs(ops_test, leader_unit_ip)

    # get initial cluster health
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip)
    assert cluster_health_resp["status"] == "green"
    assert cluster_health_resp["unassigned_shards"] == 0

    # get initial cluster allocation (nodes and their corresponding shards)
    init_shards_per_node = await get_number_of_shards_by_node(ops_test, leader_unit_ip)

    # stop service in the chosen unit
    await run_action(ops_test, unit_id_to_stop, "stop-service")

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

    if new_shards_per_node.get(unit_id_to_stop, 0) == 0:
        # all shards reallocated
        expected_health_color = "green"
    else:
        # not all shards reallocated
        expected_health_color = "yellow"

    assert cluster_health_resp["status"] == expected_health_color

    # scale up by 1 unit
    await ops_test.model.applications[APP_NAME].add_unit(count=1)
    await ops_test.model.wait_for_idle(apps=[APP_NAME], timeout=1000, wait_for_exact_units=4)

    new_unit_id = [
        int(unit.name.split("/")[1])
        for unit in ops_test.model.applications[APP_NAME].units
        if int(unit.name.split("/")[1]) not in UNIT_IDS
    ][0]

    # wait for the new unit to be active
    await ops_test.model.block_until(
        lambda: get_application_unit_status(ops_test)[new_unit_id] == "active"
    )

    # check if the unallocated shards have successfully moved to the newest unit
    new_shards_per_node = await get_number_of_shards_by_node(ops_test, leader_unit_ip)
    assert new_shards_per_node[new_unit_id] > 0

    # get new cluster health
    cluster_health_resp = await cluster_health(ops_test, leader_unit_ip)
    assert cluster_health_resp["status"] == "green"
    assert cluster_health_resp["unassigned_shards"] == 0
