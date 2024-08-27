#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from juju.application import Application
from pytest_operator.plugin import OpsTest

from ..helpers import APP_NAME, MODEL_CONFIG, SERIES, UNIT_IDS
from ..helpers_deployments import wait_until
from .helpers_manual_tls import MANUAL_TLS_CERTIFICATES_APP_NAME, ManualTLSAgent

logger = logging.getLogger(__name__)


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy_with_manual_tls(ops_test: OpsTest) -> None:
    """Build and deploy prod cluster of OpenSearch with Manual TLS Operator integration."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    os_app: Application = await ops_test.model.deploy(
        my_charm,
        num_units=len(UNIT_IDS),
        series=SERIES,
        application_name=APP_NAME,
    )

    # Deploy TLS Certificates operator.
    tls_app: Application = await ops_test.model.deploy(
        MANUAL_TLS_CERTIFICATES_APP_NAME,
        channel="stable",
    )
    await wait_until(
        ops_test,
        apps=[MANUAL_TLS_CERTIFICATES_APP_NAME],
        apps_statuses=["active"],
    )
    logger.info("Deployed %s application", MANUAL_TLS_CERTIFICATES_APP_NAME)

    # Integrate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, MANUAL_TLS_CERTIFICATES_APP_NAME)
    logger.info("Integrated %s with %s", APP_NAME, MANUAL_TLS_CERTIFICATES_APP_NAME)

    # Initialize the ManualTLSAgent to process the CSRs
    manual_tls_daemon = ManualTLSAgent(tls_app.units[0])
    # Wait for len(UNIT_IDS)*2+1 CSRs to be created.
    # 1 for each unit for http and transport and 1 for the admin cert.
    logger.info("Waiting for CSRs to be created")
    await manual_tls_daemon.wait_for_csrs_in_queue(len(UNIT_IDS) * 2 + 1)

    # Sign all CSRs
    logger.info("Signing CSRs")
    await manual_tls_daemon.process_queue()

    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(UNIT_IDS),
        timeout=2000,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == len(UNIT_IDS)

    # Scale up the application by adding a new unit
    logger.info("Scaling up the application by adding a new unit")
    await os_app.add_unit(1)

    # Wait for the new unit request certificates
    logger.info("Waiting for the new unit to request certificates")
    await manual_tls_daemon.wait_for_csrs_in_queue(2)

    # Sign all CSRs
    logger.info("Signing CSRs")
    await manual_tls_daemon.process_queue()

    # Wait for the new unit to be active
    logger.info("Waiting for the new unit to be active")
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        units_statuses=["active"],
        wait_for_exact_units=len(UNIT_IDS) + 1,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == len(UNIT_IDS) + 1
