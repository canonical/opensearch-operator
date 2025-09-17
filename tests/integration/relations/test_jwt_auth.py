#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import requests

import pytest
from pytest_operator.plugin import OpsTest

from helpers_jwt import generate_json_web_token
from ..helpers import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
    get_application_unit_ids,
    get_conf_as_dict,
    get_leader_unit_id,
    get_leader_unit_ip,
    get_secrets,
    http_request,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


DEFAULT_NUM_UNITS = 2
JWT_APP_NAME = "jwt-integrator"


@pytest.mark.abort_on_fail
async def test_deploy_small_cluster(charm, series, ops_test: OpsTest) -> None:
    """Deploy OpenSearch and JWT integrator, configure and integrate them."""
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        charm,
        num_units=3,
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
        wait_for_exact_units=3,
    )

    # todo: replace with charm name once published
    await ops_test.model.deploy("./jwt-integrator_ubuntu@24.04-amd64.charm")
    await wait_until(ops_test, apps=[JWT_APP_NAME], apps_statuses=["blocked"])


@pytest.mark.abort_on_fail
async def test_configure_jwt(charm, series, ops_test: OpsTest) -> None:
    """Configure JWT authentication and access the cluster with the token."""
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
        wait_for_exact_units={APP_NAME: 3, JWT_APP_NAME: 1},
    )

