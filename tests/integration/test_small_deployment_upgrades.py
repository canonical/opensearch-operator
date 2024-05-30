#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess

import pytest
from pytest_operator.plugin import OpsTest

from .ha.continuous_writes import ContinuousWrites
from .ha.helpers import app_name, assert_continuous_writes_consistency
from .ha.test_horizontal_scaling import IDLE_PERIOD
from .helpers import APP_NAME, MODEL_CONFIG, SERIES, run_action
from .helpers_deployments import get_application_units, wait_until
from .tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


OPENSEARCH_ORIGINAL_CHARM_NAME = "opensearch"
OPENSEARCH_CHANNEL = "2/edge"

MACHINE_ID = 0


VERSION_TO_REVISION = {
    "2.13.0": 91,
}
FIRST_VERSION = "2.12.0"
FIRST_REVISION = 90


charm = None


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


# @pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_latest_from_channel(ops_test: OpsTest) -> None:
    """Deploy OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        OPENSEARCH_ORIGINAL_CHARM_NAME,
        application_name=APP_NAME,
        num_units=3,
        channel=OPENSEARCH_CHANNEL,
        revision=FIRST_REVISION,
        series=SERIES,
    )

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config)

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=50,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_upgrade_rollback(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test upgrade from upstream to currently locally built version."""
    app = (await app_name(ops_test)) or APP_NAME
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    application = ops_test.model.applications[APP_NAME]
    action = await run_action(
        ops_test,
        leader_id,
        "pre-upgrade-check",
        app=app,
    )
    assert action.status == "completed"

    new_rev = list(VERSION_TO_REVISION.values())[-1]

    async with ops_test.fast_forward():
        logger.info("Refresh the charm")
        await application.refresh(revision=new_rev)

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                APP_NAME: 3,
            },
            idle_period=IDLE_PERIOD,
        )

        logger.info("Rolling back")
        # due to: https://github.com/juju/python-libjuju/issues/1057
        # await application.refresh(
        #     revision=rev,
        # )
        subprocess.check_output(f"juju refresh opensearch --revision={FIRST_REVISION}".split())

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units={
                APP_NAME: 3,
            },
            idle_period=IDLE_PERIOD,
        )


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_upgrade_between_versions(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test upgrade from upstream to currently locally built version."""
    app = (await app_name(ops_test)) or APP_NAME
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    for version, rev in VERSION_TO_REVISION.items():
        logger.info(f"Upgrading to version {version}")

        action = await run_action(
            ops_test,
            leader_id,
            "pre-upgrade-check",
            app=app,
        )
        assert action.status == "completed"

        async with ops_test.fast_forward():
            logger.info("Refresh the charm")
            # due to: https://github.com/juju/python-libjuju/issues/1057
            # application = ops_test.model.applications[APP_NAME]
            # await application.refresh(
            #     revision=rev,
            # )
            subprocess.check_output(f"juju refresh opensearch --revision={rev}".split())

            await wait_until(
                ops_test,
                apps=[app],
                apps_statuses=["blocked"],
                units_statuses=["active"],
                wait_for_exact_units={
                    APP_NAME: 3,
                },
                idle_period=IDLE_PERIOD,
            )

            logger.info("Upgrade finished")
            # Resume the upgrade
            action = await run_action(
                ops_test,
                leader_id,
                "resume-upgrade",
                app=app,
            )
            logger.info(action)
            assert action.status == "completed"

            logger.info("Refresh is over, waiting for the charm to settle")
            await wait_until(
                ops_test,
                apps=[app],
                apps_statuses=["active"],
                units_statuses=["active"],
                wait_for_exact_units={
                    APP_NAME: 3,
                },
                idle_period=IDLE_PERIOD,
            )


# @pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_upgrade_to_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test upgrade from usptream to currently locally built version."""
    app = (await app_name(ops_test)) or APP_NAME
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    application = ops_test.model.applications[app]
    action = await run_action(
        ops_test,
        leader_id,
        "pre-upgrade-check",
        app=app,
    )
    assert action.status == "completed"

    logger.info("Build charm locally")
    global charm
    if not charm:
        charm = await ops_test.build_charm(".")

    async with ops_test.fast_forward():
        logger.info("Refresh the charm")
        await application.refresh(path=charm)

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                APP_NAME: 3,
            },
            idle_period=120,
        )

        logger.info("Upgrade finished")
        # Resume the upgrade
        action = await run_action(
            ops_test,
            leader_id,
            "resume-upgrade",
            app=app,
        )
        logger.info(action)
        assert action.status == "completed"

        logger.info("Refresh is over, waiting for the charm to settle")
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units={
                APP_NAME: 3,
            },
            idle_period=IDLE_PERIOD,
        )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])
