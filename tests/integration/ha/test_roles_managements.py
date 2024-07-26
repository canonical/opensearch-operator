#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from charms.opensearch.v0.constants_charm import PClusterWrongNodesCountForQuorum
from pytest_operator.plugin import OpsTest

from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    check_cluster_formation_successful,
    cluster_health,
    get_application_unit_ids,
    get_application_unit_names,
    get_leader_unit_ip,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .continuous_writes import ContinuousWrites
from .helpers import all_nodes, app_name
from .test_horizontal_scaling import IDLE_PERIOD

logger = logging.getLogger(__name__)


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={TLS_CERTIFICATES_APP_NAME: 1, APP_NAME: 3},
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_set_roles_manually(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check roles changes in all nodes."""
    app = (await app_name(ops_test)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    cluster_name = (await cluster_health(ops_test, leader_unit_ip))["cluster_name"]
    nodes = await all_nodes(ops_test, leader_unit_ip)
    for node in nodes:
        assert sorted(node.roles) == [
            "cluster_manager",
            "coordinating_only",
            "data",
            "ingest",
            "ml",
        ]
        assert node.temperature is None, "Node temperature was erroneously set."

    # change cluster name and roles + temperature, should trigger a rolling restart

    logger.info("Changing cluster name and roles + temperature.")
    await ops_test.model.applications[app].set_config(
        {"cluster_name": "new_cluster_name", "roles": "cluster_manager, data.cold"}
    )
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(nodes),
        idle_period=IDLE_PERIOD,
    )

    logger.info("Checking if the cluster name and roles + temperature were changed.")
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
    )
    new_cluster_name = (await cluster_health(ops_test, leader_unit_ip))["cluster_name"]
    assert new_cluster_name == cluster_name, "Oops - cluster name changed."

    nodes = await all_nodes(ops_test, leader_unit_ip)
    for node in nodes:
        assert sorted(node.roles) == ["cluster_manager", "data"], "roles unchanged"
        assert node.temperature == "cold", "Temperature unchanged."

    # scale up cluster by 1 unit, this should give the new node the same roles
    await ops_test.model.applications[app].add_unit(count=1)
    # TODO: this should have to go once we full trust that quorum is automatically established
    await wait_until(
        ops_test,
        apps=[app],
        units_full_statuses={
            app: {
                "units": {
                    "blocked": [PClusterWrongNodesCountForQuorum],
                    "active": [],
                },
            },
        },
        wait_for_exact_units=len(nodes) + 1,
        idle_period=IDLE_PERIOD,
    )
    new_nodes = await all_nodes(ops_test, leader_unit_ip)
    assert len(new_nodes) == len(nodes)

    # remove new unit
    last_unit_id = sorted(get_application_unit_ids(ops_test, app))[-1]
    await ops_test.model.applications[app].destroy_unit(f"{app}/{last_unit_id}")


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_switch_back_to_auto_generated_roles(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check roles changes in all nodes."""
    app = (await app_name(ops_test)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    nodes = await all_nodes(ops_test, leader_unit_ip)

    await ops_test.model.applications[app].set_config({"roles": ""})
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=len(nodes),
        idle_period=IDLE_PERIOD,
    )

    # check that nodes' roles have indeed changed
    nodes = await all_nodes(ops_test, leader_unit_ip)
    for node in nodes:
        assert sorted(node.roles) == [
            "cluster_manager",
            "coordinating_only",
            "data",
            "ingest",
            "ml",
        ]
        assert node.temperature is None, "Node temperature was erroneously set."
