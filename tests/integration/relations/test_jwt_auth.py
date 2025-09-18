#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
import requests
from charms.opensearch.v0.constants_charm import JWT_CONFIG_RELATION
from pytest_operator.plugin import OpsTest

from ..helpers import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
    get_leader_unit_ip,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .helpers_jwt import generate_json_web_token

logger = logging.getLogger(__name__)


DEFAULT_NUM_UNITS = 3
JWT_APP_NAME = "jwt-integrator"
REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"
MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"
CLUSTER_NAME = "log-app"
APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 1, DATA_APP: 3}


@pytest.mark.abort_on_fail
async def test_deploy_small_cluster(charm, series, ops_test: OpsTest) -> None:
    """Deploy OpenSearch and JWT integrator, configure and integrate them."""
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        charm,
        num_units=DEFAULT_NUM_UNITS,
        series=series,
        config=CONFIG_OPTS,
    )
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
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

    # todo: replace with charm name once published
    await ops_test.model.deploy("jwt-integrator", channel="1/edge")
    await wait_until(ops_test, apps=[JWT_APP_NAME], apps_statuses=["blocked"])


@pytest.mark.abort_on_fail
async def test_configure_and_use_jwt(charm, series, ops_test: OpsTest) -> None:
    """Configure JWT authentication and access the cluster with the token."""
    global generated_jwt
    generated_jwt = generate_json_web_token()

    logger.info("Creating signing-key secret")
    secret_name = "jwt-signing-key"
    secret_id = await ops_test.model.add_secret(
        name=secret_name, data_args=[f"signing-key={generated_jwt['signing-key']}"]
    )
    await ops_test.model.grant_secret(secret_name=secret_name, application=JWT_APP_NAME)

    logger.info(f"Configuring {JWT_APP_NAME}")
    jwt_config = {
        "signing-key": secret_id,
        "roles-key": "role",
        "subject-key": "user",
    }
    await ops_test.model.applications[JWT_APP_NAME].set_config(jwt_config)

    logger.info(f"Integrating {APP_NAME} with {JWT_APP_NAME}")
    await ops_test.model.integrate(JWT_APP_NAME, APP_NAME)

    await wait_until(
        ops_test,
        apps=[APP_NAME, JWT_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={APP_NAME: DEFAULT_NUM_UNITS, JWT_APP_NAME: 1},
    )

    logger.info("Test access to `/_cat/nodes` with JWT")
    ip_address = await get_leader_unit_ip(ops_test, app=APP_NAME)
    url = f"https://{ip_address}:9200/_cat/nodes"
    result = requests.get(
        url, headers={"Authorization": f"Bearer {generated_jwt['token']}"}, verify=False
    )
    assert result.status_code == 200, "Request failed"
    logger.info("Access with JWT successful")

    # remove Opensearch to allow for follow-up test
    logger.info("Remove Opensearch cluster")
    await ops_test.model.remove_application(APP_NAME, block_until_done=True)


@pytest.mark.abort_on_fail
async def test_configure_and_use_jwt_large_cluster(charm, series, ops_test: OpsTest) -> None:
    """Create a large deployment of OpenSearch."""
    logger.info("Create large deployment cluster of Opensearch")
    await asyncio.gather(
        ops_test.model.deploy(
            charm,
            application_name=MAIN_APP,
            num_units=APP_UNITS[MAIN_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager"} | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            charm,
            application_name=FAILOVER_APP,
            num_units=APP_UNITS[FAILOVER_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "cluster_manager"}
            | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            charm,
            application_name=DATA_APP,
            num_units=APP_UNITS[DATA_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data"}
            | CONFIG_OPTS,
        ),
    )

    # integrate TLS to all applications
    for app in [MAIN_APP, FAILOVER_APP, DATA_APP]:
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    # integrate large deployment cluster
    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await ops_test.model.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{FAILOVER_APP}:{REL_ORCHESTRATOR}")

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
    )

    logger.info(f"Integrating {DATA_APP} with {JWT_APP_NAME} - this will result in blocked status")
    await ops_test.model.integrate(
        f"{JWT_APP_NAME}:{JWT_CONFIG_RELATION}",
        f"{DATA_APP}:{JWT_CONFIG_RELATION}",
    )
    await wait_until(
        ops_test,
        apps=[DATA_APP],
        units_statuses=["blocked"],
        wait_for_exact_units={DATA_APP: 3},
    )

    logger.info("Test access to `/_cat/nodes` with JWT")
    ip_address = await get_leader_unit_ip(ops_test, app=DATA_APP)
    url = f"https://{ip_address}:9200/_cat/nodes"
    result = requests.get(
        url, headers={"Authorization": f"Bearer {generated_jwt['token']}"}, verify=False
    )
    assert result.status_code == 401, "`Unauthorized` error expected"
    logger.info("Access with JWT failed as expected")

    logger.info(f"Remove relation with {DATA_APP}")
    remove_relation_cmd = (
        f"remove-relation {JWT_APP_NAME}:{JWT_CONFIG_RELATION} {DATA_APP}:{JWT_CONFIG_RELATION}"
    )
    await ops_test.juju(*remove_relation_cmd.split(), check=True)

    await wait_until(
        ops_test,
        apps=[DATA_APP],
        apps_full_statuses={DATA_APP: {"active": []}},
        units_statuses=["active"],
        wait_for_exact_units={DATA_APP: 3},
    )

    logger.info(f"Integrating {MAIN_APP} with {JWT_APP_NAME}")
    await ops_test.model.integrate(
        f"{JWT_APP_NAME}:{JWT_CONFIG_RELATION}",
        f"{MAIN_APP}:{JWT_CONFIG_RELATION}",
    )
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
    )

    logger.info("Test access to `/_cat/nodes` with JWT")
    ip_address = await get_leader_unit_ip(ops_test, app=MAIN_APP)
    url = f"https://{ip_address}:9200/_cat/nodes"
    result = requests.get(
        url, headers={"Authorization": f"Bearer {generated_jwt['token']}"}, verify=False
    )
    assert result.status_code == 200, "Request failed"
    logger.info("Access with JWT successful")
