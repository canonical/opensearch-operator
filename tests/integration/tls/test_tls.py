#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    check_cluster_formation_successful,
    get_application_unit_ips_names,
    get_application_unit_names,
    get_leader_unit_id,
    get_leader_unit_ip,
    run_action,
)
from ..helpers_deployments import wait_until
from ..tls.helpers import (
    check_security_index_initialised,
    check_unit_tls_configured,
    get_loaded_tls_certificates,
)

logger = logging.getLogger(__name__)


TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy_active(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        my_charm,
        num_units=len(UNIT_IDS),
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
        wait_for_exact_units=len(UNIT_IDS),
    )
    assert len(ops_test.model.applications[APP_NAME].units) == len(UNIT_IDS)


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_security_index_initialised(ops_test: OpsTest) -> None:
    """Test that the security index is well initialised."""
    # Wait for the leader unit to initialize the security index.
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    assert await check_security_index_initialised(ops_test, leader_unit_ip)


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_tls_configured(ops_test: OpsTest) -> None:
    """Test that TLS is enabled when relating to the TLS Certificates Operator."""
    for unit_name, unit_ip in (await get_application_unit_ips_names(ops_test)).items():
        assert await check_unit_tls_configured(ops_test, unit_ip, unit_name)


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_cluster_formation_after_tls(ops_test: OpsTest) -> None:
    """Test that the cluster formation is successful after TLS setup."""
    unit_names = get_application_unit_names(ops_test)
    leader_unit_ip = await get_leader_unit_ip(ops_test)

    assert await check_cluster_formation_successful(ops_test, leader_unit_ip, unit_names)


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_tls_renewal_without_restart(ops_test: OpsTest) -> None:
    """Test that renewed TLS certificates are reloaded immediately without restarting."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    current_certs = await get_loaded_tls_certificates(leader_unit_ip)

    leader_id = await get_leader_unit_id(ops_test)
    await run_action(ops_test, leader_id, "set-tls-private-key", {"category": "unit-http"})

    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(UNIT_IDS),
        timeout=30,
    )

    updated_certs = await get_loaded_tls_certificates(leader_unit_ip)

    assert (
        updated_certs["http_certificates_list"][0]["not_before"]
        > current_certs["http_certificates_list"][0]["not_before"]
    )
