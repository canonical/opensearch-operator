#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import app_name, assert_continuous_writes_consistency
from tests.integration.helpers import APP_NAME, MODEL_CONFIG, SERIES, UNIT_IDS
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


OPENSEARCH_INITIAL_CHANNEL = "2/edge"


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
async def test_deploy_latest_from_channel(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        APP_NAME,
        channel="2/edge",
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
        idle_period=50,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == len(UNIT_IDS)


@pytest.mark.abort_on_fail
async def test_upgrade_from_channel(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test that the security index is well initialised."""
    # Wait for the leader unit to initialize the security index.
    app = (await app_name(ops_test)) or APP_NAME

    application = ops_test.model.applications[APP_NAME]
    logger.info("Build charm locally")

    global charm
    charm = await ops_test.build_charm(".")

    logger.info("Refresh the charm")
    await application.refresh(path=charm)

    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1400,
        idle_period=50,
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
