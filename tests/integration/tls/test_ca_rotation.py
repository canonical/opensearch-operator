#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import APP_NAME, MODEL_CONFIG, SERIES
from ..helpers_deployments import wait_until

logger = logging.getLogger(__name__)


TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy_active(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        my_charm,
        # TODO: run tests with three units once the voting exclusions issue is resolved
        # num_units=len(UNIT_IDS),
        num_units=5,
        series=SERIES,
    )

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config)
    await wait_until(ops_test, apps=[TLS_CERTIFICATES_APP_NAME], apps_statuses=["active"])

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        timeout=1800,
        # TODO: run tests with three units once the voting exclusions issue is resolved
        # wait_for_exact_units=len(UNIT_IDS),
        wait_for_exact_units=5,
    )


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_rollout_new_ca(ops_test: OpsTest) -> None:
    """Test that the cluster restarted and functional after processing a new CA certificate"""
    new_config = {"ca-common-name": "NEW_CA"}

    # trigger a rollout of the new CA by changing the config on TLS Provider side
    await ops_test.model.applications[TLS_CERTIFICATES_APP_NAME].set_config(new_config)

    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        timeout=1000,
        idle_period=60,
        # TODO: run tests with three units once the voting exclusions issue is resolved
        # wait_for_exact_units=len(UNIT_IDS),
        wait_for_exact_units=5,
    )
