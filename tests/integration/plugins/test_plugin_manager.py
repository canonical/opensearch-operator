#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
from typing import Tuple

import pytest
from charms.opensearch.v0.constants_charm import PeerRelationName
from pytest_operator.plugin import OpsTest

from ..helpers import (
    CONFIG_OPTS,
    MODEL_CONFIG,
)
from ..helpers_deployments import wait_until
from ..relations.helpers import get_application_relation_data

logger = logging.getLogger(__name__)


SMTP_INTEGRATOR = "smtp-integrator"
TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"
TLS_STABLE_CHANNEL = "latest/stable"

REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"

MAIN_APP = "opensearch-main"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "plugin-manager"
APP_UNITS = {MAIN_APP: 3, DATA_APP: 2}


async def list_keystore_keys(ops_test: OpsTest, app: str, unit_id: int) -> Tuple[str, str]:
    """List keys in OpenSearch keystore on given unit"""
    logger.info(f"Running command on {app}/{unit_id}: sudo snap run opensearch.keystore list")
    _, stdout, _ = await ops_test.juju(
        "exec",
        "--model",
        ops_test.model.name,
        "--unit",
        f"{app}/{unit_id}",
        "--",
        "sudo",
        "snap",
        "run",
        "opensearch.keystore",
        "list",
    )

    return f"{app}/{unit_id}", stdout.split("\n")


async def get_secret_data(ops_test, secret_uri):
    """Get secret data from secret uri"""
    secret_unique_id = secret_uri.split("/")[-1]
    complete_command = f"show-secret {secret_uri} --reveal --format=json"
    _, stdout, _ = await ops_test.juju(*complete_command.split())
    return json.loads(stdout)[secret_unique_id]["content"]["Data"]


SMTP_KEYS = [
    "opensearch.notifications.core.email.smtp.user.password",
    "opensearch.notifications.core.email.smtp.user.username",
]


@pytest.mark.skip_if_deployed
@pytest.mark.abort_on_fail
async def test_build_and_deploy_active(ops_test: OpsTest, charm, series) -> None:
    """Build test environment"""
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy large deployment of OpenSearch, TLS Certificates operator and SMTP integrator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(
            charm,
            application_name=MAIN_APP,
            num_units=APP_UNITS[MAIN_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME} | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            charm,
            application_name=DATA_APP,
            num_units=APP_UNITS[DATA_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data.hot,ml"}
            | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            SMTP_INTEGRATOR,
            channel="latest/edge",
        ),
    )

    # wait until the TLS operator is ready
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME],
        status="active",
    )

    # Relate it to OpenSearch to set up TLS.
    for app in list(APP_UNITS.keys()):
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await ops_test.model.wait_for_idle(
        apps=[MAIN_APP, DATA_APP],
        status="active",
    )
    await ops_test.model.wait_for_idle(apps=[SMTP_INTEGRATOR], status="blocked")


@pytest.mark.abort_on_fail
async def test_smtp_credentials_written_to_keystore(ops_test: OpsTest) -> None:
    """Test that SMTP credentials are written to the OpenSearch keystore."""
    config = {"user": "smtp.user", "password": "supersecret", "host": "smtp.host"}
    await ops_test.model.applications[SMTP_INTEGRATOR].set_config(config)
    await ops_test.model.integrate(f"{SMTP_INTEGRATOR}:smtp", MAIN_APP)

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, SMTP_INTEGRATOR],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=APP_UNITS | {SMTP_INTEGRATOR: 1},
    )

    # ensure keys are written on all units
    check_keys = []
    for app, n_units in APP_UNITS.items():
        for unit_id in range(n_units):
            check_keys.append(list_keystore_keys(ops_test, app, unit_id))

    results = await asyncio.gather(*check_keys)
    logger.info("Checking if expected keys written to all nodes")
    for unit_id, keys in results:
        for expected_key in SMTP_KEYS:
            assert expected_key in keys, f"{unit_id} is missing expected key {expected_key}"
    logger.info("All keys written")


@pytest.mark.abort_on_fail
async def test_smtp_credentials_changed(ops_test: OpsTest) -> None:
    """Test that SMTP credentials secret is updated."""
    new_password = "moresecret"
    config = {"password": new_password}
    await ops_test.model.applications[SMTP_INTEGRATOR].set_config(config)

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, SMTP_INTEGRATOR],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=APP_UNITS | {SMTP_INTEGRATOR: 1},
    )
    plugins = await get_application_relation_data(
        ops_test, f"{DATA_APP}/0", PeerRelationName, "plugin_config_info"
    )

    label = "plugin-notifications"
    secret_uri = json.loads(plugins).get(label).get("secret_id")
    secret_content = await get_secret_data(ops_test, secret_uri)
    data = json.loads(secret_content.get(label))

    password_key = "opensearch.notifications.core.email.smtp.user.password"
    password = data.get("keys").get(password_key)
    assert password == new_password, f"Expected password {new_password} but found {password}"


@pytest.mark.abort_on_fail
async def test_smtp_credentials_removed_from_keystore(ops_test: OpsTest) -> None:
    """Test that SMTP credentials are removed from the OpenSearch keystore."""
    # remove stmp relation
    await ops_test.model.applications[MAIN_APP].destroy_relation(
        f"{SMTP_INTEGRATOR}:smtp", MAIN_APP
    )
    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, SMTP_INTEGRATOR],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=APP_UNITS | {SMTP_INTEGRATOR: 1},
    )

    check_keys = []
    for app, n_units in APP_UNITS.items():
        for unit_id in range(n_units):
            check_keys.append(list_keystore_keys(ops_test, app, unit_id))

    results = await asyncio.gather(*check_keys)
    logger.info("Checking if keys removed from all nodes")
    for unit_id, keys in results:
        for expected_key in SMTP_KEYS:
            assert expected_key not in keys, f"{unit_id} still has key {expected_key}"
    logger.info("All keys removed.")
