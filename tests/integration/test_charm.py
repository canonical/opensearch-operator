#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import APP_NAME, MODEL_CONFIG, SERIES, UNIT_IDS

logger = logging.getLogger(__name__)


@pytest.mark.charm_tests
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
    await ops_test.model.wait_for_idle(wait_for_exact_units=len(UNIT_IDS))


@pytest.mark.charm_tests
@pytest.mark.abort_on_fail
async def test_status(ops_test: OpsTest) -> None:
    """Verifies that the application and unit are active."""
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="blocked", timeout=1000, wait_for_exact_units=len(UNIT_IDS)
    )
    assert len(ops_test.model.applications[APP_NAME].units) == len(UNIT_IDS)
