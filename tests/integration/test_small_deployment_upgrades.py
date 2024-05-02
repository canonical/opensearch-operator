#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

from .ha.continuous_writes import ContinuousWrites
from .ha.helpers import app_name, assert_continuous_writes_consistency
from .helpers import APP_NAME, MODEL_CONFIG, SERIES, run_action
from .helpers_deployments import get_application_units, wait_until
from .tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


OPENSEARCH_INITIAL_CHANNEL = "latest/edge"
MACHINE_ID = 0


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


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_latest_from_channel(ops_test: OpsTest) -> None:
    """Deploy OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        "pguimaraes-opensearch-upgrade-test",
        application_name=APP_NAME,
        num_units=3,
        channel=OPENSEARCH_INITIAL_CHANNEL,
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
    """Test upgrade from usptream to currently locally built version."""
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
            apps_full_statuses={
                "blocked": [
                    "Upgrading. Verify highest unit is healthy & run `resume-upgrade` "
                    "action. To rollback, `juju refresh` to last revision"
                ]
            },
            idle_period=50,
        )

    logger.info("Rolling back")
    # Facing the same issue as descripted in:
    # https://github.com/juju/python-libjuju/issues/924
    # application = ops_test.model.applications[APP_NAME]
    # await application.refresh(
    #     switch="ch:pguimaraes-opensearch-upgrade-test",
    #     channel=OPENSEARCH_INITIAL_CHANNEL,
    # )
    subprocess.check_output(
        f"juju refresh {app} --switch "
        "pguimaraes-opensearch-upgrade-test --channel latest/edge".split(),
    )
    async with ops_test.fast_forward():
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            idle_period=50,
        )


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_upgrade_to_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test upgrade from usptream to currently locally built version."""
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
            apps_full_statuses={
                "blocked": [
                    "Upgrading. Verify highest unit is healthy & run `resume-upgrade` "
                    "action. To rollback, `juju refresh` to last revision"
                ]
            },
            idle_period=50,
        )
        logger.info("Upgrade finished")
        # Wait for the upgrade to converge and update its own state
        for attempt in Retrying(stop=stop_after_delay(3 * 60), wait=wait_fixed(30)):
            with attempt:
                # Resume the upgrade
                action = await run_action(
                    ops_test,
                    leader_id,
                    "resume-upgrade",
                    app=app,
                )
                assert action.status == "completed"

    logger.info("Refresh is over, waiting for the charm to settle")
    await wait_until(
        ops_test,
        apps=[app],
        apps_statuses=["active"],
        units_statuses=["active"],
        idle_period=50,
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_accidental_downgrade_status(ops_test: OpsTest) -> None:
    """Test if we rollback the change above, by accident."""
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

    logger.info("Refresh the charm back to the original version")
    # Facing the same issue as descripted in:
    # https://github.com/juju/python-libjuju/issues/924
    # application = ops_test.model.applications[APP_NAME]
    # await application.refresh(
    #     switch="ch:pguimaraes-opensearch-upgrade-test",
    #     channel=OPENSEARCH_INITIAL_CHANNEL,
    # )
    subprocess.check_output(
        f"juju refresh {app} --switch "
        "pguimaraes-opensearch-upgrade-test --channel latest/edge".split(),
    )

    await wait_until(
        ops_test,
        apps=[app],
        apps_full_statuses={
            "blocked": ["Upgrade incompatible. Rollback to previous revision with `juju refresh`"]
        },
        idle_period=50,
    )


# @pytest.mark.group("failed_upgrade")
# @pytest.mark.abort_on_fail
# @pytest.mark.skip_if_deployed
# async def test_deploy_latest_from_channel(ops_test: OpsTest) -> None:
#     """Deploy OpenSearch."""
#     await ops_test.model.set_config(MODEL_CONFIG)

#     await ops_test.model.deploy(
#         "pguimaraes-opensearch-upgrade-test",
#         application_name=APP_NAME,
#         num_units=3,
#         channel=OPENSEARCH_INITIAL_CHANNEL,
#         series=SERIES,
#     )

#     # We want opensearch to be nodes 0-2
#     await asyncio.sleep(15)

#     # Deploy TLS Certificates operator.
#     config = {"ca-common-name": "CN_CA"}
#     await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config)

#     # Relate it to OpenSearch to set up TLS.
#     await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
#     await ops_test.model.wait_for_idle(
#         apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
#         status="active",
#         timeout=1400,
#         idle_period=50,
#     )
#     assert len(ops_test.model.applications[APP_NAME].units) == 3


# @pytest.mark.group("failed_upgrade")
# @pytest.mark.abort_on_fail
# async def test_upgrade_and_fail_unit(
#     ops_test: OpsTest
# ) -> None:
#     """Test upgrade from usptream to currently locally built version."""
#     app = (await app_name(ops_test)) or APP_NAME
#     units = await get_application_units(ops_test, app)
#     leader_id = [u.id for u in units if u.is_leader][0]

#     application = ops_test.model.applications[APP_NAME]
#     action = await run_action(
#         ops_test,
#         leader_id,
#         "pre-upgrade-check",
#         app=app,
#     )
#     assert action.status == "completed"

#     logger.info("Build charm locally")
#     global charm
#     if not charm:
#         charm = await ops_test.build_charm(".")

#     async with ops_test.fast_forward():
#         logger.info("Refresh the charm")
#         await application.refresh(path=charm)

#         await wait_until(
#             ops_test,
#             apps=[app],
#             apps_full_statuses={
#                 "blocked": [
#                     "Upgrading. Verify highest unit is healthy & run `resume-upgrade` "
#                     "action. To rollback, `juju refresh` to last revision"
#                 ]
#             },
#             idle_period=50,
#         )

#     logger.info(f"Now, power down unit services in machine {MACHINE_ID}")
#     for system_file in ["snap.opensearch.daemon", f"jujud-machine-{MACHINE_ID}"]:
#         subprocess.check_output(
#             f"juju exec {MACHINE_ID} -- sudo systemctl stop {system_file}".split()
#         )

#     async with ops_test.fast_forward():
#         logger.info("Resume upgrade")
#         # Wait for the upgrade to converge and update its own state
#         for attempt in Retrying(stop=stop_after_delay(3 * 60), wait=wait_fixed(30)):
#             with attempt:
#                 # Resume the upgrade
#                 action = await run_action(
#                     ops_test,
#                     leader_id,
#                     "resume-upgrade",
#                     app=app,
#                 )
#                 assert action.status == "completed"

#     logger.info("Refresh is over, waiting for the charm to settle")
#     await wait_until(
#         ops_test,
#         apps=[app],
#         apps_statuses=["active"],
#         units_statuses=["active"],
#         idle_period=50,
#     )
