#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest
from charms.opensearch.v0.constants_charm import PClusterNoDataNode, PClusterNoRelation

from ..ha.continuous_writes import ContinuousWrites
from ..ha.helpers import (
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
)
from ..helpers import APP_NAME, CONFIG_OPTS, MODEL_CONFIG, run_action
from ..helpers_deployments import get_application_units, wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .helpers import refresh

logger = logging.getLogger(__name__)

IDLE_PERIOD = 30
INITIAL_REVISION_NOBLE = 206
INITIAL_REVISION_JAMMY = 207
OPENSEARCH_ORIGINAL_CHARM_NAME = "opensearch"
OPENSEARCH_INITIAL_CHANNEL = "2/edge"
MAIN_APP = "main"
FAILOVER_APP = "failover"
TIMEOUT = 2400

REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"

charm = None


WORKLOAD = {
    APP_NAME: 3,
    FAILOVER_APP: 2,
    MAIN_APP: 3,
}


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_large_deployment_deploy_original_charm(ops_test: OpsTest, series) -> None:
    """Build and deploy the charm for large deployment tests."""
    await ops_test.model.set_config(MODEL_CONFIG)

    initial_revision = INITIAL_REVISION_JAMMY if series == "jammy" else INITIAL_REVISION_NOBLE

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(
            OPENSEARCH_ORIGINAL_CHARM_NAME,
            channel=OPENSEARCH_INITIAL_CHANNEL,
            application_name=MAIN_APP,
            num_units=WORKLOAD[MAIN_APP],
            revision=initial_revision,
            series=series,
            config={"cluster_name": "upgrades" } | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            OPENSEARCH_ORIGINAL_CHARM_NAME,
            channel=OPENSEARCH_INITIAL_CHANNEL,
            application_name=FAILOVER_APP,
            num_units=WORKLOAD[FAILOVER_APP],
            revision=initial_revision,
            series=series,
            config={"cluster_name": "upgrades", "init_hold": True, "roles": "cluster_manager"}
            | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            OPENSEARCH_ORIGINAL_CHARM_NAME,
            channel=OPENSEARCH_INITIAL_CHANNEL,
            application_name=APP_NAME,
            num_units=WORKLOAD[APP_NAME],
            revision=initial_revision,
            series=series,
            config={"cluster_name": "upgrades", "init_hold": True, "roles": "data"}
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
    for app in [MAIN_APP, FAILOVER_APP, APP_NAME]:
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    # confirm all apps are blocked because NO TLS relation established
    await wait_until(
        ops_test,
        apps=list(WORKLOAD.keys()),
        apps_full_statuses={
            MAIN_APP: {"active": []},
            FAILOVER_APP: {"blocked": [PClusterNoRelation]},
            APP_NAME: {"blocked": [PClusterNoRelation]},
        },
        units_full_statuses={
            MAIN_APP: {"units": {"active": []}},
            FAILOVER_APP: {"units": {"active": []}},
            APP_NAME: {"units": {"active": []}},
        },
        wait_for_exact_units={app: units for app, units in WORKLOAD.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )

    await ops_test.model.integrate(f"{MAIN_APP}:{REL_ORCHESTRATOR}", f"{APP_NAME}:{REL_PEER}")
    await ops_test.model.integrate(f"{MAIN_APP}:{REL_ORCHESTRATOR}", f"{FAILOVER_APP}:{REL_PEER}")
    await ops_test.model.integrate(f"{FAILOVER_APP}:{REL_ORCHESTRATOR}", f"{APP_NAME}:{REL_PEER}")

    await wait_until(
        ops_test,
        apps=list(WORKLOAD.keys()),
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={app: units for app, units in WORKLOAD.items()},
        idle_period=IDLE_PERIOD,
        timeout=1800,
    )


# @pytest.mark.group(id="happy_path_upgrade")
# @pytest.mark.abort_on_fail
# async def test_upgrade_between_versions(ops_test: OpsTest):
#     pass


async def assert_upgrade(ops_test: OpsTest, c_writes: ContinuousWrites, charm: str, app):
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    action = await run_action(
        ops_test,
        leader_id,
        "pre-upgrade-check",
        app=app,
    )
    assert action.status == "completed"
    async with ops_test.fast_forward(fast_interval="60s"):
        logger.info("Refresh the charm")

        await refresh(ops_test, app, path=charm, config={"profile": "testing"})

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={app: WORKLOAD[app]},
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        # Resume the upgrade
        action = await run_action(
            ops_test,
            leader_id,
            "resume-upgrade",
            app=app,
        )
        assert action.status == "completed"
        logger.info(f"resume-upgrade: {action}")

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info(f"Upgrade of app {app} finished")


@pytest.mark.abort_on_fail
async def test_manually_upgrade_to_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, charm
) -> None:
    """Test upgrade from upstream to currently locally built version."""
    for app in list(WORKLOAD.keys()):
        await assert_upgrade(ops_test, c_writes, charm, app)

    # continuous writes checks
    # await assert_continuous_writes_increasing(c_writes)
    # await assert_continuous_writes_consistency(ops_test, c_writes, list(WORKLOAD.keys()))

    # units = await get_application_units(ops_test, MAIN_APP)
    # leader_id = [u.id for u in units if u.is_leader][0]
    #
    # action = await run_action(
    #     ops_test,
    #     leader_id,
    #     "pre-upgrade-check",
    #     app=MAIN_APP,
    # )
    # assert action.status == "completed"
    #
    # logger.info("Build charm locally")
    #
    # async with ops_test.fast_forward(fast_interval="60s"):
    #     for app, unit_count in WORKLOAD.items():
    #         application = ops_test.model.applications[app]
    #         units = await get_application_units(ops_test, app)
    #         leader_id = [u.id for u in units if u.is_leader][0]
    #
    #         logger.info(f"Refresh app {app}, leader {leader_id}")
    #
    #         await application.refresh(path=charm)
    #         logger.info("Refresh is over, waiting for the charm to settle")
    #
    #         if unit_count == 1:
    #             # Upgrade already happened for this unit, wait for idle and continue
    #             await wait_until(
    #                 ops_test,
    #                 apps=[app],
    #                 apps_statuses=["active"],
    #                 units_statuses=["active"],
    #                 idle_period=IDLE_PERIOD,
    #                 timeout=3600,
    #             )
    #             logger.info(f"Upgrade of app {app} finished")
    #             continue
    #
    #         await wait_until(
    #             ops_test,
    #             apps=[app],
    #             apps_statuses=["blocked"],
    #             units_statuses=["active"],
    #             wait_for_exact_units={
    #                 app: unit_count,
    #             },
    #             idle_period=IDLE_PERIOD,
    #             timeout=3600,
    #         )
    #         # Resume the upgrade
    #         action = await run_action(
    #             ops_test,
    #             leader_id,
    #             "resume-upgrade",
    #             app=app,
    #         )
    #         assert action.status == "completed"
    #         logger.info(f"resume-upgrade: {action}")
    #
    #         await wait_until(
    #             ops_test,
    #             apps=[app],
    #             apps_statuses=["active"],
    #             units_statuses=["active"],
    #             idle_period=IDLE_PERIOD,
    #             timeout=3600,
    #         )
    #         logger.info(f"Upgrade of app {app} finished")
