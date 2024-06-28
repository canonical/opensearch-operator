#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import APP_NAME, MODEL_CONFIG, SERIES
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


DEFAULT_NUM_UNITS = 1


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, lxd_spaces) -> None:
    """Build and deploy OpenSearch.

    For this test, we will misconfigure space bindings and see if the charm still
    respects the setup.

    More information: gh:canonical/opensearch-operator#334
    """
    # my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Create a deployment that binds to the wrong space.
    # That should trigger #334.
    await ops_test.model.deploy(
        # my_charm,
        "opensearch",
        channel="2/edge",
        num_units=DEFAULT_NUM_UNITS,
        series=SERIES,
        constraints="spaces=alpha,client,cluster,backup",
        bind={"": "cluster"},
    )
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel="stable",
        constraints="spaces=alpha,client,cluster,backup",
        bind={"": "cluster"},
        config=config,
    )
    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=DEFAULT_NUM_UNITS,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == DEFAULT_NUM_UNITS


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_check_opensearch_transport(ops_test: OpsTest) -> None:
    """Test which IP will be assigned to transport bind in the end."""
