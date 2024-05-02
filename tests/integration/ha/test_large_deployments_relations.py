#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from charms.opensearch.v0.constants_charm import (
    PClusterNoRelation,
    TLSNotFullyConfigured,
    TLSRelationMissing,
)
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
INVALID_APP = "opensearch-invalid"

CLUSTER_NAME = "log-app"
INVALID_CLUSTER_NAME = "timeseries"


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
            num_units=3,
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME},
        ),
        ops_test.model.deploy(
            my_charm,
            application_name=FAILOVER_APP,
            num_units=3,
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True},
        ),
        ops_test.model.deploy(
            my_charm,
            application_name=DATA_APP,
            num_units=2,
            series=SERIES,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data.hot,ml"},
        ),
        ops_test.model.deploy(
            my_charm,
            application_name=INVALID_APP,
            num_units=1,
            series=SERIES,
            config={"cluster_name": INVALID_CLUSTER_NAME, "init_hold": True, "roles": "data.cold"},
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

    # confirm all apps are blocked because NO TLS relation established
    apps_units = {MAIN_APP: 3, FAILOVER_APP: 3, DATA_APP: 2, INVALID_APP: 1}
    await wait_until(
        ops_test,
        apps=list(apps_units.keys()),
        apps_full_statuses={
            MAIN_APP: {"blocked": [TLSRelationMissing]},
            FAILOVER_APP: {"blocked": [PClusterNoRelation]},
            DATA_APP: {"blocked": [PClusterNoRelation]},
            INVALID_APP: {"blocked": [PClusterNoRelation]},
        },
        units_full_statuses={
            MAIN_APP: {"units": {"blocked": [TLSRelationMissing]}},
            FAILOVER_APP: {"units": {"active": []}},
            DATA_APP: {"units": {"active": []}},
            INVALID_APP: {"units": {"active": []}},
        },
        wait_for_exact_units={app: units for app, units in apps_units.items()},
        idle_period=IDLE_PERIOD,
    )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_invalid_conditions(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check invalid conditions under different states."""
    # integrate an app with the main-orchestrator when TLS is not related to the provider
    await ops_test.model.integrate(
        f"{MAIN_APP}:{REL_ORCHESTRATOR}", f"{FAILOVER_APP}:{REL_PEER}"
    )
    await wait_until(
        ops_test,
        apps=[MAIN_APP, FAILOVER_APP],
        apps_full_statuses={
            MAIN_APP: {"blocked": [TLSRelationMissing]},
            FAILOVER_APP: {
                "blocked": ["TLS not fully configured in related 'main-orchestrator'."]
            },
        },
        idle_period=IDLE_PERIOD,
    )

    # integrate TLS to all applications
    for app in [MAIN_APP, FAILOVER_APP, DATA_APP, INVALID_APP]:
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    await wait_until(
        ops_test,
        apps=[MAIN_APP, FAILOVER_APP, DATA_APP, INVALID_APP],
        apps_full_statuses={
            MAIN_APP: {"active": []},
            FAILOVER_APP: {"active": []},
            DATA_APP: {"blocked": [TLSNotFullyConfigured]},
            INVALID_APP: {"blocked": [TLSNotFullyConfigured]},
        },
        idle_period=IDLE_PERIOD,
    )

    # fetch nodes, we should have 6 nodes (main + failover)-orchestrators
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=MAIN_APP)
    nodes = await all_nodes(ops_test, leader_unit_ip)
    assert len(nodes) == 6

    # integrate cluster with different name
    await ops_test.model.integrate(
        f"{MAIN_APP}:{REL_ORCHESTRATOR}", f"{INVALID_APP}:{REL_PEER}"
    )
    await wait_until(
        ops_test,
        apps=[INVALID_APP],
        apps_full_statuses={
            INVALID_APP: {
                "blocked": ["Cannot relate 2 clusters with different 'cluster_name' values."]
            },
        },
        idle_period=IDLE_PERIOD,
    )

    # delete the invalid app name
    await ops_test.model.remove_application(
        INVALID_APP, block_until_done=True, force=True, destroy_storage=True, no_wait=True
    )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_large_deployment_fully_formed(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test that under optimal conditions all the nodes form the same big cluster."""
    await ops_test.model.integrate(
        f"{MAIN_APP}:{REL_ORCHESTRATOR}", f"{DATA_APP}:{REL_PEER}"
    )
    await ops_test.model.integrate(
        f"{FAILOVER_APP}:{REL_ORCHESTRATOR}", f"{DATA_APP}:{REL_PEER}"
    )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, FAILOVER_APP, DATA_APP],
        apps_statuses=["active"],
        units_statuses=["active"],
        idle_period=IDLE_PERIOD,
    )

    # fetch nodes, we should have 6 nodes (main + failover)-orchestrators
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=MAIN_APP)
    nodes = await all_nodes(ops_test, leader_unit_ip)
    assert len(nodes) == 8, f"Wrong node count: {len(nodes)}"

    # check the roles
    auto_gen_roles = ["cluster_manager", "coordinating_only", "data", "ingest", "ml"]
    data_roles = ["data", "ml"]
    for app, node_count in [(MAIN_APP, 3), (FAILOVER_APP, 3), (DATA_APP, 2)]:
        current_app_nodes = [node for node in nodes if node.app_name == app]
        assert (
            len(current_app_nodes) == node_count
        ), f"Wrong count for {app}:{len(current_app_nodes)} - expected:{node_count}"

        roles = current_app_nodes[0].roles
        temperature = current_app_nodes[0].temperature
        if app in [MAIN_APP, FAILOVER_APP]:
            assert sorted(roles) == sorted(
                [auto_gen_roles]
            ), f"Wrong roles for {app}:{roles} - expected:{auto_gen_roles}"
            assert temperature is None, f"Wrong temperature for {app}:{roles} - expected:None"
        else:
            assert sorted(roles) == sorted(
                [data_roles]
            ), f"Wrong roles for {app}:{roles} - expected:{data_roles}"
            assert (
                temperature == "cold"
            ), f"Wrong temperature for {app}:{temperature} - expected:cold"
