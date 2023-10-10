#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import all_nodes, app_name, update_restart_delay
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    check_cluster_formation_successful,
    cluster_health,
    get_application_unit_ids,
    get_application_unit_names,
    get_leader_unit_ip,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


SECOND_APP_NAME = "second-opensearch"
ORIGINAL_RESTART_DELAY = 20
RESTART_DELAY = 360


@pytest.fixture()
async def reset_restart_delay(ops_test: OpsTest):
    """Resets service file delay on all units."""
    yield
    app = (await app_name(ops_test)) or APP_NAME
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, ORIGINAL_RESTART_DELAY)


@pytest.fixture()
async def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    app = (await app_name(ops_test)) or APP_NAME
    return ContinuousWrites(ops_test, app)


@pytest.fixture()
async def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture()
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    await c_writes.start(repl_on_all_nodes=True)
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


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
    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 2


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
    await ops_test.model.applications[app].set_config(
        {"cluster_name": "new_cluster_name", "roles": "cluster_manager, data.cold"}
    )
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        idle_period=IDLE_PERIOD,
    )
    assert await check_cluster_formation_successful(
        ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
    )
    new_cluster_name = (await cluster_health(ops_test, leader_unit_ip))["cluster_name"]
    assert new_cluster_name == cluster_name, "Oops - cluster name changed."

    nodes = await all_nodes(ops_test, leader_unit_ip)
    for node in nodes:
        assert sorted(node.roles) == ["cluster_manager", "data"], "roles unchanged"
        assert node.temperature == "cold", "Temperature unchanged."

    # scale up cluster by 1 unit, this should break the quorum and put the charm in a blocked state
    await ops_test.model.applications[app].add_unit(count=1)
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="blocked",
        timeout=1000,
        wait_for_exact_units=4,
        idle_period=IDLE_PERIOD,
    )
