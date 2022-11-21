#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.helpers import get_shards_by_state
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    check_cluster_formation_successful,
    get_application_unit_names,
    get_leader_unit_ip,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


@pytest.mark.ha_tests
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of MongoDB."""
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
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)


@pytest.mark.ha_tests
@pytest.mark.abort_on_fail
async def test_horizontal_scale_up(ops_test: OpsTest) -> None:
    """Tests that new added units to the cluster are discoverable."""
    # scale up
    await ops_test.model.applications[APP_NAME].add_unit(count=2)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=5
    )
    num_units = len(ops_test.model.applications[APP_NAME].units)
    assert num_units == 5

    unit_names = get_application_unit_names(ops_test)
    leader_unit_ip = await get_leader_unit_ip(ops_test)

    assert await check_cluster_formation_successful(ops_test, leader_unit_ip, unit_names)

    shards_by_status = await get_shards_by_state(ops_test, leader_unit_ip)
    assert not shards_by_status.get("INITIALIZING")
    assert not shards_by_status.get("RELOCATING")
    assert not shards_by_status.get("UNASSIGNED")
