#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
import requests
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..helpers import (
    APP_NAME,
    IDLE_PERIOD,
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    get_leader_unit_ip,
    get_secret_by_label,
)
from ..helpers_deployments import wait_until

logger = logging.getLogger(__name__)


TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"

REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"

MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "log-app"

APP_UNITS = {MAIN_APP: 2, FAILOVER_APP: 1, DATA_APP: 2}


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


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_build_large_deployment(ops_test: OpsTest) -> None:
    """Setup a large deployments cluster."""
    # remove the existing application
    await ops_test.model.remove_application(APP_NAME, block_until_done=True)

    # deploy new cluster
    my_charm = await ops_test.build_charm(".")
    await asyncio.gather(
        ops_test.model.deploy(
            my_charm,
            application_name=MAIN_APP,
            num_units=2,
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager,data"},
        ),
        ops_test.model.deploy(
            my_charm,
            application_name=FAILOVER_APP,
            num_units=1,
            series=SERIES,
            config={
                "cluster_name": CLUSTER_NAME,
                "init_hold": True,
                "roles": "cluster_manager,data",
            },
        ),
        ops_test.model.deploy(
            my_charm,
            application_name=DATA_APP,
            num_units=2,
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data"},
        ),
    )

    # integrate TLS to all applications
    for app in [MAIN_APP, FAILOVER_APP, DATA_APP]:
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    # create the peer-cluster-relation
    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await ops_test.model.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{FAILOVER_APP}:{REL_ORCHESTRATOR}")

    # wait for the cluster to fully form
    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP],
        apps_full_statuses={
            MAIN_APP: {"active": []},
            DATA_APP: {"active": []},
            FAILOVER_APP: {"active": []},
        },
        units_statuses=["active"],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
    )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_rollout_new_ca_large_deployment(ops_test: OpsTest) -> None:
    """Repeat the CA rotation test for the large deployment."""
    c_writes = ContinuousWrites(ops_test, DATA_APP)
    await c_writes.start()

    # trigger a rollout of the new CA by changing the config on TLS Provider side
    new_config = {"ca-common-name": "EVEN_NEWER_CA"}
    await ops_test.model.applications[TLS_CERTIFICATES_APP_NAME].set_config(new_config)

    writes_count = await c_writes.count()

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP],
        apps_full_statuses={
            MAIN_APP: {"active": []},
            DATA_APP: {"active": []},
            FAILOVER_APP: {"active": []},
        },
        units_statuses=["active"],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        timeout=2400,
        idle_period=IDLE_PERIOD,
    )

    more_writes = await c_writes.count()
    await c_writes.stop()
    assert more_writes > writes_count, "Writes have not continued during CA rotation"

    # using the SSL API requires authentication with app-admin cert and key
    leader_unit_ip = await get_leader_unit_ip(ops_test, DATA_APP)
    url = f"https://{leader_unit_ip}:9200/_plugins/_security/api/ssl/certs"
    admin_secret = await get_secret_by_label(ops_test, "opensearch-data:app:app-admin")

    with open("admin.cert", "w") as cert:
        cert.write(admin_secret["cert"])

    with open("admin.key", "w") as key:
        key.write(admin_secret["key"])

    response = requests.get(url, cert=("admin.cert", "admin.key"), verify=False)
    data = response.json()
    assert new_config["ca-common-name"] in data["http_certificates_list"][0]["issuer_dn"]
