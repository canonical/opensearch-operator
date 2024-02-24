#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest

from pytest_operator.plugin import OpsTest
from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    app_name,
    assert_continuous_writes_consistency,
)
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    get_leader_unit_id,
    run_action,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


OPENSEARCH_INITIAL_CHANNEL = "2/edge"


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_latest_from_channel(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # TODO: re-add this when the charm has upgrade action implemented in edge
    # await ops_test.model.deploy(
    #     APP_NAME,
    #     num_units=len(UNIT_IDS),
    #     series=SERIES,
    #     channel=OPENSEARCH_INITIAL_CHANNEL
    # )
    await ops_test.model.deploy(
        my_charm,
        num_units=len(UNIT_IDS),
        series=SERIES,
    )

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config)

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == len(UNIT_IDS)


@pytest.mark.abort_on_fail
async def test_upgrade_from_channel(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test that the security index is well initialised."""
    # Wait for the leader unit to initialize the security index.
    app = (await app_name(ops_test)) or APP_NAME
    leader_id = await get_leader_unit_id(ops_test)

    action = await run_action(ops_test, leader_id, "pre-upgrade-check")
    logger.debug(f"pre-upgrade-check output: {action}")
    assert action.status == "completed"

    application = ops_test.model.applications[APP_NAME]
    logger.info("Build charm locally")

    global charm
    charm = await ops_test.build_charm(".")

    logger.info("Refresh the charm")
    await application.refresh(path=charm)

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)