#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from charms.opensearch.v0.constants_charm import PClusterWrongNodesCountForQuorum
from pytest_operator.plugin import OpsTest

from ..helpers import CONFIG_OPTS, MODEL_CONFIG, SERIES
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .test_horizontal_scaling import IDLE_PERIOD

logger = logging.getLogger(__name__)

REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"

MAIN_APP = "opensearch-main"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "log-app"

APP_UNITS = {MAIN_APP: 2, DATA_APP: 1}


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(
            my_charm,
            application_name=MAIN_APP,
            num_units=APP_UNITS[MAIN_APP],
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME} | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            my_charm,
            application_name=DATA_APP,
            num_units=APP_UNITS[DATA_APP],
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data.hot,ml"}
            | CONFIG_OPTS,
        ),
    )

    # wait until the TLS operator is ready
    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={TLS_CERTIFICATES_APP_NAME: 1},
        idle_period=IDLE_PERIOD,
    )

    # integrate TLS to all applications
    for app in [MAIN_APP, DATA_APP]:
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP],
        apps_full_statuses={
            MAIN_APP: {"active": []},
            DATA_APP: {"active": []},
        },
        units_statuses=["active"],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_large_deployment_validate_cm_count(ops_test: OpsTest) -> None:
    """Test that scaling down to less than 3 cms triggers a status change"""
    # scale main down to 1 units
    main_app = ops_test.model.applications[MAIN_APP]
    await main_app.destroy_units(main_app.units[-1].name)

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP],
        apps_full_statuses={
            DATA_APP: {"active": []},
            MAIN_APP: {"blocked": [PClusterWrongNodesCountForQuorum]},
        },
        units_statuses=["active"],
        wait_for_exact_units={
            MAIN_APP: 1,
            DATA_APP: APP_UNITS[DATA_APP],
        },
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    # check that the status is cleared on scale up to >= 3 cms
    await ops_test.model.applications[MAIN_APP].add_units(2)
    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={
            MAIN_APP: 3,
            DATA_APP: APP_UNITS[DATA_APP],
        },
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )
