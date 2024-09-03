#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
import requests
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    get_leader_unit_ip,
    get_secret_by_label,
)
from ..helpers_deployments import wait_until

logger = logging.getLogger(__name__)


TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
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
        timeout=1800,
        wait_for_exact_units=len(UNIT_IDS),
    )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_rollout_new_ca(ops_test: OpsTest) -> None:
    """Test that the cluster restarted and functional after processing a new CA certificate"""
    c_writes = ContinuousWrites(ops_test, APP_NAME)
    await c_writes.start()

    # trigger a rollout of the new CA by changing the config on TLS Provider side
    new_config = {"ca-common-name": "NEW_CA"}
    await ops_test.model.applications[TLS_CERTIFICATES_APP_NAME].set_config(new_config)

    writes_count = await c_writes.count()

    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        timeout=1800,
        idle_period=60,
        wait_for_exact_units=len(UNIT_IDS),
    )

    more_writes = await c_writes.count()
    await c_writes.stop()
    assert more_writes > writes_count, "Writes have not continued during CA rotation"

    # using the SSL API requires authentication with app-admin cert and key
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    url = f"https://{leader_unit_ip}:9200/_plugins/_security/api/ssl/certs"
    admin_secret = await get_secret_by_label(ops_test, "opensearch:app:app-admin")

    with open("admin.cert", "w") as cert:
        cert.write(admin_secret["cert"])

    with open("admin.key", "w") as key:
        key.write(admin_secret["key"])

    response = requests.get(url, cert=("admin.cert", "admin.key"), verify=False)
    data = response.json()
    assert new_config["ca-common-name"] in data["http_certificates_list"][0]["issuer_dn"]