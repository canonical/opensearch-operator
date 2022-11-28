#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    check_cluster_formation_successful,
    get_application_unit_ips_names,
    get_application_unit_names,
    get_leader_unit_ip,
)
from tests.integration.tls.helpers import (
    check_security_index_initialised,
    check_unit_tls_configured,
)

logger = logging.getLogger(__name__)

TLS_CERTIFICATES_APP_NAME = "tls-certificates-operator"


@pytest.mark.tls_tests
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy_active(ops_test: OpsTest) -> None:
    """Build and deploy one unit of MongoDB."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        my_charm,
        num_units=len(UNIT_IDS),
        series=SERIES,
    )
    await ops_test.model.wait_for_idle()
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


@pytest.mark.tls_tests
@pytest.mark.abort_on_fail
async def test_security_index_initialised(ops_test: OpsTest) -> None:
    """Test that the security index is well initialised."""
    # Wait for the leader unit to initialize the security index.
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    assert await check_security_index_initialised(ops_test, leader_unit_ip)


@pytest.mark.tls_tests
@pytest.mark.abort_on_fail
async def test_tls_configured(ops_test: OpsTest) -> None:
    """Test that TLS is enabled when relating to the TLS Certificates Operator."""
    for unit_name, unit_ip in get_application_unit_ips_names(ops_test).items():
        assert await check_unit_tls_configured(ops_test, unit_ip, unit_name)


@pytest.mark.tls_tests
@pytest.mark.abort_on_fail
async def test_cluster_formation_after_tls(ops_test: OpsTest) -> None:
    """Test that the cluster formation is successful after TLS setup."""
    unit_names = get_application_unit_names(ops_test)
    leader_unit_ip = await get_leader_unit_ip(ops_test)

    assert await check_cluster_formation_successful(ops_test, leader_unit_ip, unit_names)
