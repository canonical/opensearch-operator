#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..ha.helpers import get_elected_cm_unit_id
from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    cluster_health,
    get_leader_unit_ip,
    set_watermark,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .continuous_writes import ContinuousWrites
from .helpers import (
    app_name,
    assert_continuous_writes_consistency,
    cluster_voting_config_exclusions,
)
from .test_horizontal_scaling import IDLE_PERIOD

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

    await set_watermark(ops_test, app=APP_NAME)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_scale_down(ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner) -> None:
    """Tests the shutdown of a node, and see the voting exclusions to be applied.

    This test will remove the elected cluster manager.
    """
    app = (await app_name(ops_test)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    voting_exclusions = await cluster_voting_config_exclusions(ops_test, unit_ip=leader_unit_ip)
    assert len(voting_exclusions) == 0

    init_count = len(ops_test.model.applications[app].units)
    while init_count > 1:
        # find unit currently elected cluster_manager
        leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
        elected_cm_unit_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)

        # remove the service in the chosen unit
        await ops_test.model.applications[app].destroy_unit(f"{app}/{elected_cm_unit_id}")
        await wait_until(
            ops_test,
            apps=[app],
            units_statuses=["active"],
            wait_for_exact_units=init_count - 1,
            idle_period=IDLE_PERIOD,
        )

        # get initial cluster health - expected to be all good: green
        leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
        cluster_health_resp = await cluster_health(
            ops_test, leader_unit_ip, wait_for_green_first=True
        )
        assert cluster_health_resp["status"] == "green"
        assert cluster_health_resp["unassigned_shards"] == 0

        voting_exclusions = await cluster_voting_config_exclusions(
            ops_test, unit_ip=leader_unit_ip
        )

        if init_count == 3:
            assert len(voting_exclusions) == 2
        elif init_count == 2:
            assert len(voting_exclusions) == 1
        init_count = len(ops_test.model.applications[app].units)

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_scale_back_up(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Tests the scaling back to 3x node-cluster and see the voting exclusions to be applied."""
    app = (await app_name(ops_test)) or APP_NAME

    init_count = len(ops_test.model.applications[app].units)
    while init_count < 3:
        # find unit currently elected cluster_manager
        leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

        # remove the service in the chosen unit
        await ops_test.model.applications[app].add_unit(count=1)
        await wait_until(
            ops_test,
            apps=[app],
            units_statuses=["active"],
            wait_for_exact_units=init_count + 1,
            idle_period=IDLE_PERIOD,
        )

        # get initial cluster health - expected to be all good: green
        leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
        cluster_health_resp = await cluster_health(
            ops_test, leader_unit_ip, wait_for_green_first=True
        )
        assert cluster_health_resp["status"] == "green"
        assert cluster_health_resp["unassigned_shards"] == 0

        voting_exclusions = await cluster_voting_config_exclusions(
            ops_test, unit_ip=leader_unit_ip
        )
        if init_count == 1:
            assert len(voting_exclusions) == 1
        elif init_count == 2:
            assert len(voting_exclusions) == 0
        init_count = len(ops_test.model.applications[app].units)

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])
