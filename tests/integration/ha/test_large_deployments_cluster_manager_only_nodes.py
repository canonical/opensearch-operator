#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time

import pytest
from charms.opensearch.v0.constants_charm import PClusterNoDataNode, PClusterNoRelation
from pytest_operator.plugin import OpsTest

from ..helpers import MODEL_CONFIG, SERIES, get_leader_unit_ip
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .continuous_writes import ContinuousWrites
from .helpers import all_nodes
from .test_horizontal_scaling import IDLE_PERIOD

logger = logging.getLogger(__name__)

REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"

MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "log-app"

APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 1, DATA_APP: 2}


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
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(
            my_charm,
            application_name=MAIN_APP,
            num_units=1,
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager"},
        ),
        ops_test.model.deploy(
            my_charm,
            application_name=FAILOVER_APP,
            num_units=1,
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "cluster_manager"},
        ),
        ops_test.model.deploy(
            my_charm,
            application_name=DATA_APP,
            num_units=2,
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data"},
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
    for app in [MAIN_APP, FAILOVER_APP, DATA_APP]:
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    # confirm all apps are blocked because NO TLS relation established
    await wait_until(
        ops_test,
        apps=list(APP_UNITS.keys()),
        apps_full_statuses={
            MAIN_APP: {"blocked": [PClusterNoDataNode]},
            FAILOVER_APP: {"blocked": [PClusterNoRelation]},
            DATA_APP: {"blocked": [PClusterNoRelation]},
        },
        units_full_statuses={
            MAIN_APP: {"units": {"blocked": [PClusterNoDataNode]}},
            FAILOVER_APP: {"units": {"active": []}},
            DATA_APP: {"units": {"active": []}},
        },
        wait_for_exact_units={app: units for app, units in APP_UNITS.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_correct_startup_after_integration(ops_test: OpsTest) -> None:
    """After integrating the cluster manager with the data application, both should start up."""
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
    )

    # make sure data can be written
    c_writes = ContinuousWrites(ops_test, app=DATA_APP)
    await c_writes.start()
    time.sleep(30)
    await c_writes.stop()
    assert (await c_writes.count()) > 0, "Continuous writes did not increase"

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=MAIN_APP)
    nodes = await all_nodes(ops_test, leader_unit_ip, app=MAIN_APP)
    assert len(nodes) == 3, f"Wrong node count. Expecting 3 online nodes, found: {len(nodes)}."


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_integrate_failover(ops_test: OpsTest) -> None:
    """After integrating the failover app to the others, all should be started and fine."""
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
        idle_period=IDLE_PERIOD,
    )

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=MAIN_APP)
    nodes = await all_nodes(ops_test, leader_unit_ip, app=MAIN_APP)
    assert len(nodes) == 4, f"Wrong node count. Expecting 4 online nodes, found: {len(nodes)}."
