#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import time

from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..helpers import APP_NAME, IDLE_PERIOD, app_name, run_action
from ..helpers_deployments import get_application_units, wait_until

OPENSEARCH_SERVICE_PATH = "/etc/systemd/system/snap.opensearch.daemon.service"
ORIGINAL_RESTART_DELAY = 20
SECOND_APP_NAME = "second-opensearch"
RESTART_DELAY = 360


logger = logging.getLogger(__name__)


async def assert_upgrade_to_local(
    ops_test: OpsTest, cwrites: ContinuousWrites, local_charm: str
) -> None:
    """Does the upgrade to local and asserts continuous writes."""
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

    async with ops_test.fast_forward():
        logger.info("Refresh the charm")
        await application.refresh(path=local_charm)

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

    # continuous writes checks
    writes_count = await cwrites.count()
    time.sleep(30)
    assert await cwrites.count() > writes_count, "Continuous writes not increasing"
