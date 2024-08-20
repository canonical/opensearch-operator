#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess
import time

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    check_cluster_formation_successful,
    get_application_unit_ids,
    get_application_unit_ids_ips,
    get_application_unit_ips_names,
    get_application_unit_names,
    get_leader_unit_id,
    get_leader_unit_ip,
    is_up,
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
async def test_tls_renewal(ops_test: OpsTest) -> None:
    """Test that renewed TLS certificates are reloaded immediately without restarting."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    leader_id = await get_leader_unit_id(ops_test)
    non_leader_id = [
        unit_id for unit_id in get_application_unit_ids(ops_test) if unit_id != leader_id
    ][0]
    units = await get_application_unit_ids_ips(ops_test, APP_NAME)

    # test against the leader unit for unit-transport cert
    current_certs = await get_loaded_tls_certificates(ops_test, leader_unit_ip)
    await run_action(
        ops_test, leader_id, "set-tls-private-key", params={"category": "unit-transport"}
    )

    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(UNIT_IDS),
        idle_period=15,
        timeout=60,
    )

    updated_certs = await get_loaded_tls_certificates(ops_test, leader_unit_ip)
    assert (
        updated_certs["transport_certificates_list"][0]["not_before"]
        > current_certs["transport_certificates_list"][0]["not_before"]
    )

    # test against a random non-leader unit for unit-http cert
    current_certs = await get_loaded_tls_certificates(ops_test, units[non_leader_id])
    await run_action(
        ops_test,
        non_leader_id,
        action_name="set-tls-private-key",
        params={"category": "unit-http"},
    )

    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(UNIT_IDS),
        idle_period=5,
        timeout=30,
    )

    updated_certs = await get_loaded_tls_certificates(ops_test, units[non_leader_id])
    assert (
        updated_certs["http_certificates_list"][0]["not_before"]
        > current_certs["http_certificates_list"][0]["not_before"]
    )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_tls_expiration(ops_test: OpsTest) -> None:
    """Test that expiring TLS certificates are renewed."""
    # before we can run this test, need to clean up and deploy with different config
    await ops_test.model.remove_application(APP_NAME, block_until_done=True)
    await ops_test.model.remove_application(TLS_CERTIFICATES_APP_NAME, block_until_done=True)

    # Deploy TLS Certificates operator
    config = {"ca-common-name": "CN_CA", "certificate-validity": "1"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config)
    await wait_until(ops_test, apps=[TLS_CERTIFICATES_APP_NAME], apps_statuses=["active"])

    # Deploy Opensearch operator
    await ops_test.model.set_config(MODEL_CONFIG)
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(
        my_charm,
        num_units=1,
        series=SERIES,
    )

    await wait_until(
        ops_test,
        apps=[APP_NAME],
        units_statuses=["blocked"],
        wait_for_exact_units=1,
    )

    # Now apply a hack to make the certificate secrets expire in short time
    # set the secret expiry to a fixed timedelta of 300 seconds to give time to start initially
    # this happens on the tls_certificates lib and we apply the patch via sed-command
    search_expression = "expire=self._get_next_secret_expiry_time\\(certificate\\)"
    replace_expression = "expire=timedelta\\(seconds=180\\)"

    unit_id = get_application_unit_ids(ops_test, APP_NAME)[0]
    unit_ip = await get_leader_unit_ip(ops_test)
    lib_file = f"/var/lib/juju/agents/unit-opensearch-{unit_id}/charm/lib/charms/tls_certificates_interface/v3/tls_certificates.py"
    cmd = f"juju ssh {APP_NAME}/{unit_id} sudo sed -i 's/{search_expression}/{replace_expression}/g' {lib_file}"
    subprocess.run(cmd, shell=True)

    # Relate OpenSearch to TLS and wait until all is settled
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    assert await is_up(ops_test, unit_ip), "OpenSearch service hasn't started."

    # now start with the actual test
    # first get the currently used certs
    current_certs = await get_loaded_tls_certificates(ops_test, unit_ip)

    # now wait for the expiration period to pass by (and a bit longer for things to settle)
    # we can't use `wait_until` here because the unit might not be idle in the meantime
    time.sleep(360)

    # now compare the current certificates against the earlier ones and see if they were updated
    updated_certs = await get_loaded_tls_certificates(ops_test, unit_ip)

    assert (
        updated_certs["transport_certificates_list"][0]["not_before"]
        > current_certs["transport_certificates_list"][0]["not_before"]
    )
