#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess

import pytest
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..ha.helpers import app_name, assert_upgrade_to_local
from ..helpers import (
    APP_NAME,
    IDLE_PERIOD,
    MODEL_CONFIG,
    SERIES,
    run_action,
    set_watermark,
)
from ..helpers_deployments import get_application_units, wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


OPENSEARCH_ORIGINAL_CHARM_NAME = "opensearch"
OPENSEARCH_CHANNEL = "2/edge"


STARTING_VERSION = "2.12.0"


VERSION_TO_REVISION = {
    STARTING_VERSION: 90,
    "2.13.0": 91,
}


FROM_VERSION_PREFIX = "from_v{}_to_local"


UPGRADE_INITIAL_VERSION = [
    (
        pytest.param(
            version,
            id=FROM_VERSION_PREFIX.format(version),
            marks=pytest.mark.group(FROM_VERSION_PREFIX.format(version)),
        )
    )
    for version in VERSION_TO_REVISION.keys()
]


charm = None


#######################################################################
#
#  Auxiliary functions
#
#######################################################################


async def _build_env(ops_test: OpsTest, version: str) -> None:
    """Deploy OpenSearch cluster from a given revision."""
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        OPENSEARCH_ORIGINAL_CHARM_NAME,
        application_name=APP_NAME,
        num_units=3,
        channel=OPENSEARCH_CHANNEL,
        revision=VERSION_TO_REVISION[version],
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

    await set_watermark(ops_test, APP_NAME)


#######################################################################
#
#  Tests
#
#######################################################################


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group("happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_latest_from_channel(ops_test: OpsTest) -> None:
    """Deploy OpenSearch."""
    await _build_env(ops_test, STARTING_VERSION)


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group("happy_path_upgrade")
@pytest.mark.abort_on_fail
async def test_upgrade_between_versions(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test upgrade from upstream to currently locally built version."""
    app = (await app_name(ops_test)) or APP_NAME
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    for version, rev in VERSION_TO_REVISION.items():
        if version == STARTING_VERSION:
            # We're starting in this version
            continue

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
                timeout=1400,
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
                timeout=1400,
                idle_period=IDLE_PERIOD,
            )


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "xlarge"])
@pytest.mark.group("happy_path_upgrade")
@pytest.mark.abort_on_fail
async def test_upgrade_to_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test upgrade from usptream to currently locally built version."""
    logger.info("Build charm locally")
    charm = await ops_test.build_charm(".")
    await assert_upgrade_to_local(ops_test, c_writes, charm)


##################################################################################
#
#  test scenarios from each version:
#    Start with each version, moving to local and then rolling back mid-upgrade
#    Once this test passes, the 2nd test will rerun the upgrade, this time to
#    its end.
#
##################################################################################


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
    app = (await app_name(ops_test)) or APP_NAME
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

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
        # due to: https://github.com/juju/python-libjuju/issues/1057
        # application = ops_test.model.applications[APP_NAME]
        # await application.refresh(
        #     revision=new_rev,
        # )
        subprocess.check_output(f"juju refresh opensearch --path={charm}".split())

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                APP_NAME: 3,
            },
            timeout=1400,
            idle_period=IDLE_PERIOD,
        )

        logger.info(f"Rolling back to {version}")
        # due to: https://github.com/juju/python-libjuju/issues/1057
        # await application.refresh(
        #     revision=rev,
        # )

        # Rollback operation
        # We must first switch back to the upstream charm, then rollback to the original
        # revision we were using.
        subprocess.check_output(
            f"""juju refresh opensearch
                 --switch={OPENSEARCH_ORIGINAL_CHARM_NAME}
                 --channel={OPENSEARCH_CHANNEL}""".split()
        )

        # Wait until we are set in an idle state and can rollback the revision.
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                APP_NAME: 3,
            },
            timeout=1400,
            idle_period=IDLE_PERIOD,
        )

        subprocess.check_output(
            f"juju refresh opensearch --revision={VERSION_TO_REVISION[version]}".split()
        )

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units={
                APP_NAME: 3,
            },
            timeout=1400,
            idle_period=IDLE_PERIOD,
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
