#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging

import pytest
from charms.opensearch.v0.constants_charm import (
    PClusterOrchestratorsRemoved,
    PeerRelationName,
)
from charms.opensearch.v0.models import (
    DeploymentDescription,
    DeploymentType,
    PeerClusterOrchestrators,
)
from pytest_operator.plugin import OpsTest

from ..helpers import CONFIG_OPTS, MODEL_CONFIG
from ..helpers_deployments import wait_until
from ..relations.helpers import get_application_relation_data
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .test_horizontal_scaling import IDLE_PERIOD

logger = logging.getLogger(__name__)

REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"

MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "app"

APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 3, DATA_APP: 1}


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, charm, series) -> None:
    """Build and deploy one unit of OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
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
            config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager"} | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            charm,
            application_name=FAILOVER_APP,
            num_units=APP_UNITS[FAILOVER_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager", "init_hold": True}
            | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            charm,
            application_name=DATA_APP,
            num_units=APP_UNITS[DATA_APP],
            series=series,
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


@pytest.mark.abort_on_fail
async def test_large_deployment_remove_orchestrators(ops_test: OpsTest) -> None:
    """Test that the orchestrator apps can be deleted."""
    unit = ops_test.model.applications[MAIN_APP].units[-1]
    deployment_desc = await get_application_relation_data(
        ops_test, unit_name=unit.name, relation_name=PeerRelationName, key="deployment-description"
    )
    deployment_desc = DeploymentDescription.from_dict(json.loads(deployment_desc))

    assert deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR

    # delete the main orchestrator
    await ops_test.model.remove_application(
        MAIN_APP,
    )
    # failover should be promoted
    await wait_until(
        ops_test,
        apps=[FAILOVER_APP, DATA_APP],
        apps_full_statuses={
            FAILOVER_APP: {"active": []},
            DATA_APP: {"active": []},
        },
        units_statuses=["active"],
        wait_for_exact_units={
            DATA_APP: APP_UNITS[DATA_APP],
            FAILOVER_APP: APP_UNITS[FAILOVER_APP],
        },
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    unit = ops_test.model.applications[FAILOVER_APP].units[-1]
    deployment_desc = await get_application_relation_data(
        ops_test, unit_name=unit.name, relation_name=PeerRelationName, key="deployment-description"
    )
    deployment_desc = DeploymentDescription.from_dict(json.loads(deployment_desc))

    assert deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR

    # get orchestrators registered in data app
    unit = ops_test.model.applications[DATA_APP].units[-1]
    orchestrators = await get_application_relation_data(
        ops_test, unit_name=unit.name, relation_name=PeerRelationName, key="orchestrators"
    )
    # ensure failover is the new main and that no failover is registered
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert orchestrators.main_app.name == FAILOVER_APP
    assert orchestrators.failover_app is None

    # delete the main orchestrator (which is now failover)
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
