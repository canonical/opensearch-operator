#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from charms.opensearch.v0.constants_charm import (
    PClusterOrchestratorsRemoved,
    PClusterWaitingForFailoverPromotion,
)
from pytest_operator.plugin import OpsTest

from ..helpers import CONFIG_OPTS, MODEL_CONFIG, SERIES
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .test_horizontal_scaling import IDLE_PERIOD

logger = logging.getLogger(__name__)

REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"

MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "app"

APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 2, DATA_APP: 1}


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
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
            application_name=FAILOVER_APP,
            num_units=APP_UNITS[FAILOVER_APP],
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True} | CONFIG_OPTS,
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
    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={TLS_CERTIFICATES_APP_NAME: 1},
        idle_period=IDLE_PERIOD,
    )

    # integrate TLS to all applications
    for app in [MAIN_APP, FAILOVER_APP, DATA_APP]:
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    await ops_test.model.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await ops_test.model.integrate(f"{DATA_APP}:{REL_PEER}", f"{FAILOVER_APP}:{REL_ORCHESTRATOR}")
    await wait_until(
        ops_test,
        apps=[MAIN_APP, FAILOVER_APP, DATA_APP],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_large_deployment_sever_main_failover_relation(ops_test: OpsTest) -> None:
    """Test that the main-failover relation can be removed and re-added."""
    await ops_test.model.applications[MAIN_APP].remove_relation(
        f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}"
    )
    await wait_until(
        ops_test,
        apps=[MAIN_APP, FAILOVER_APP, DATA_APP],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )
    # re-relate main and failover
    await ops_test.model.integrate(f"{FAILOVER_APP}:{REL_PEER}", f"{MAIN_APP}:{REL_ORCHESTRATOR}")
    await wait_until(
        ops_test,
        apps=[MAIN_APP, FAILOVER_APP, DATA_APP],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_large_deployment_remove_orchestrators(ops_test: OpsTest) -> None:
    """Test that the orchestrator apps can be deleted."""
    # delete the main orchestrator
    await ops_test.model.remove_application(
        MAIN_APP,
        block_until_done=True,
        destroy_storage=True,
    )
    await wait_until(
        ops_test,
        apps=[FAILOVER_APP, DATA_APP],
        apps_full_statuses={
            FAILOVER_APP: {"active": []},
            DATA_APP: {"waiting": [PClusterWaitingForFailoverPromotion]},
        },
        units_statuses=["active"],
        wait_for_exact_units={
            DATA_APP: APP_UNITS[DATA_APP],
            FAILOVER_APP: APP_UNITS[FAILOVER_APP],
        },
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    # delete the failover orchestrator
    await ops_test.model.remove_application(
        FAILOVER_APP,
    )
    await wait_until(
        ops_test,
        apps=[DATA_APP],
        apps_full_statuses={
            DATA_APP: {"blocked": [PClusterOrchestratorsRemoved]},
        },
        units_statuses=["active"],
        wait_for_exact_units={
            DATA_APP: APP_UNITS[DATA_APP],
        },
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )
