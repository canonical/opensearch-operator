#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..ha.helpers import assert_continuous_writes_consistency
from ..helpers import (
    APP_NAME,
    IDLE_PERIOD,
    MODEL_CONFIG,
    SERIES,
    get_leader_unit_id,
    run_action,
    set_watermark,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .helpers import (
    OPENSEARCH_CHANNEL,
    OPENSEARCH_ORIGINAL_CHARM_NAME,
    STARTING_VERSION,
    UPGRADE_INITIAL_VERSION,
    VERSION_TO_REVISION,
    assert_upgrade_to_local,
    refresh,
)

logger = logging.getLogger(__name__)


OPENSEARCH_MAIN_APP_NAME = "main"
OPENSEARCH_FAILOVER_APP_NAME = "failover"


charm = None


WORKLOAD = {
    APP_NAME: 2,
    OPENSEARCH_FAILOVER_APP_NAME: 1,
    OPENSEARCH_MAIN_APP_NAME: 3,
}


#######################################################################
#
#  Auxiliary functions
#
#######################################################################
async def _build_env(ops_test: OpsTest, version: str) -> None:
    """Deploy OpenSearch cluster from a given revision."""
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    tls_config = {"ca-common-name": "CN_CA"}

    main_orchestrator_conf = {
        "cluster_name": "backup-test",
        "init_hold": False,
        "roles": "cluster_manager",
    }
    failover_orchestrator_conf = {
        "cluster_name": "backup-test",
        "init_hold": True,
        "roles": "cluster_manager",
    }
    data_conf = {"cluster_name": "backup-test", "init_hold": True, "roles": "data"}

    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=tls_config),
        ops_test.model.deploy(
            OPENSEARCH_ORIGINAL_CHARM_NAME,
            application_name=OPENSEARCH_MAIN_APP_NAME,
            num_units=WORKLOAD[OPENSEARCH_MAIN_APP_NAME],
            series=SERIES,
            channel=OPENSEARCH_CHANNEL,
            config=main_orchestrator_conf,
        ),
        ops_test.model.deploy(
            OPENSEARCH_ORIGINAL_CHARM_NAME,
            application_name=OPENSEARCH_FAILOVER_APP_NAME,
            num_units=WORKLOAD[OPENSEARCH_FAILOVER_APP_NAME],
            series=SERIES,
            channel=OPENSEARCH_CHANNEL,
            config=failover_orchestrator_conf,
        ),
        ops_test.model.deploy(
            OPENSEARCH_ORIGINAL_CHARM_NAME,
            application_name=APP_NAME,
            num_units=WORKLOAD[APP_NAME],
            series=SERIES,
            channel=OPENSEARCH_CHANNEL,
            config=data_conf,
        ),
    )

    # Large deployment setup
    await ops_test.model.integrate("main:peer-cluster-orchestrator", "failover:peer-cluster")
    await ops_test.model.integrate("main:peer-cluster-orchestrator", f"{APP_NAME}:peer-cluster")
    await ops_test.model.integrate(
        "failover:peer-cluster-orchestrator", f"{APP_NAME}:peer-cluster"
    )

    # TLS setup
    await ops_test.model.integrate("main", TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate("failover", TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)

    # Charms except s3-integrator should be active
    await wait_until(
        ops_test,
        apps=[
            TLS_CERTIFICATES_APP_NAME,
            OPENSEARCH_MAIN_APP_NAME,
            OPENSEARCH_FAILOVER_APP_NAME,
            APP_NAME,
        ],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={
            TLS_CERTIFICATES_APP_NAME: 1,
            OPENSEARCH_MAIN_APP_NAME: WORKLOAD[OPENSEARCH_MAIN_APP_NAME],
            OPENSEARCH_FAILOVER_APP_NAME: WORKLOAD[OPENSEARCH_FAILOVER_APP_NAME],
            APP_NAME: WORKLOAD[APP_NAME],
        },
        idle_period=IDLE_PERIOD,
        timeout=3600,
    )

    await set_watermark(ops_test, APP_NAME)


async def _upgrade(ops_test: OpsTest, local_build: bool = False, revision: str = None) -> None:
    app = OPENSEARCH_MAIN_APP_NAME
    leader_id = await get_leader_unit_id(ops_test, app)
    action = await run_action(
        ops_test,
        leader_id,
        "pre-upgrade-check",
        app=OPENSEARCH_MAIN_APP_NAME,
    )
    assert action.status == "completed"

    logger.info("Build charm locally")
    global charm
    if not charm:
        charm = await ops_test.build_charm(".")

    async with ops_test.fast_forward():
        for app, unit_count in WORKLOAD.items():
            leader_id = get_leader_unit_id(ops_test, app)

            logger.info(f"Refresh app {app}, leader {leader_id}")

            if local_build:
                await refresh(ops_test, app, path=charm)
            else:
                await refresh(ops_test, app, revision=revision)
            logger.info("Refresh is over, waiting for the charm to settle")

            if unit_count == 1:
                # Upgrade already happened for this unit, wait for idle and continue
                await wait_until(
                    ops_test,
                    apps=[app],
                    apps_statuses=["active"],
                    units_statuses=["active"],
                    idle_period=IDLE_PERIOD,
                    timeout=3600,
                )
                logger.info(f"Upgrade of app {app} finished")
                continue

            # Wait until we are set in an idle state and can rollback the revision.
            # app status blocked: that will happen if we are jumping N-2 versions in our test
            # app status active: that will happen if we are jumping N-1 in our test
            await wait_until(
                ops_test,
                apps=[app],
                apps_statuses=["active", "blocked"],
                units_statuses=["active"],
                wait_for_exact_units={
                    app: unit_count,
                },
                idle_period=120,
                timeout=3600,
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
                idle_period=IDLE_PERIOD,
                timeout=3600,
            )
            logger.info(f"Upgrade of app {app} finished")


#######################################################################
#
#  Tests
#
#######################################################################
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group("happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_large_deployment_deploy_original_charm(ops_test: OpsTest) -> None:
    """Deploy OpenSearch."""
    await _build_env(ops_test, STARTING_VERSION)


@pytest.mark.group("happy_path_upgrade")
@pytest.mark.abort_on_fail
async def test_upgrade_between_versions(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test upgrade from upstream to currently locally built version."""
    for version, rev in VERSION_TO_REVISION.items():
        if version == STARTING_VERSION:
            # We're starting in this version
            continue

        logger.info(f"Upgrading to version {version}")
        await _upgrade(ops_test, revision=rev)

    await _upgrade(ops_test, local_build=True)
    # continuous writes checks
    await assert_continuous_writes_consistency(
        ops_test,
        c_writes,
        [APP_NAME, OPENSEARCH_MAIN_APP_NAME],
    )


##################################################################################
#
#  test scenarios from each version:
#    Start with each version, moving to local and then rolling back mid-upgrade
#    Once this test passes, the 2nd test will rerun the upgrade, this time to
#    its end.
#
##################################################################################
@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.parametrize("version", UPGRADE_INITIAL_VERSION)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_from_version(ops_test: OpsTest, version) -> None:
    """Deploy OpenSearch."""
    await _build_env(ops_test, version)


@pytest.mark.parametrize("version", UPGRADE_INITIAL_VERSION)
@pytest.mark.abort_on_fail
async def test_upgrade_rollback_from_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, version
) -> None:
    """Test upgrade and rollback to each version available."""
    app = OPENSEARCH_MAIN_APP_NAME
    leader_id = await get_leader_unit_id(ops_test, app)
    action = await run_action(
        ops_test,
        leader_id,
        "pre-upgrade-check",
        app=OPENSEARCH_MAIN_APP_NAME,
    )
    assert action.status == "completed"

    logger.info("Build charm locally")
    global charm
    if not charm:
        charm = await ops_test.build_charm(".")

    async with ops_test.fast_forward():
        logger.info(f"Refresh app {app}, leader {leader_id}")

    async with ops_test.fast_forward():
        for app, unit_count in WORKLOAD.items():
            leader_id = get_leader_unit_id(ops_test, app)

            await refresh(ops_test, app, path=charm)
            logger.info("Refresh is over, waiting for the charm to settle")

            # Wait until we are set in an idle state and can rollback the revision.
            # app status blocked: that will happen if we are jumping N-2 versions in our test
            # app status active: that will happen if we are jumping N-1 in our test
            await wait_until(
                ops_test,
                apps=[app],
                apps_statuses=["active", "blocked"],
                units_statuses=["active"],
                wait_for_exact_units={
                    app: unit_count,
                },
                idle_period=120,
                timeout=3600,
            )

    # continuous writes checks
    await assert_continuous_writes_consistency(
        ops_test,
        c_writes,
        [APP_NAME, OPENSEARCH_MAIN_APP_NAME],
    )


@pytest.mark.parametrize("version", UPGRADE_INITIAL_VERSION)
@pytest.mark.abort_on_fail
async def test_upgrade_from_version_to_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, version
) -> None:
    """Test upgrade from usptream to currently locally built version."""
    logger.info("Build charm locally")
    global charm
    if not charm:
        charm = await ops_test.build_charm(".")
    await assert_upgrade_to_local(ops_test, c_writes, charm)
