#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess
from typing import Optional

from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_attempt, wait_fixed

from ..ha.continuous_writes import ContinuousWrites
from ..ha.helpers import (
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
)
from ..helpers import APP_NAME, IDLE_PERIOD, app_name, run_action
from ..helpers_deployments import get_application_units, wait_until

OPENSEARCH_SERVICE_PATH = "/etc/systemd/system/snap.opensearch.daemon.service"
ORIGINAL_RESTART_DELAY = 20
SECOND_APP_NAME = "second-opensearch"
RESTART_DELAY = 360


logger = logging.getLogger(__name__)


async def refresh(
    ops_test: OpsTest,
    app_name: str,
    *,
    revision: Optional[int] = None,
    switch: Optional[str] = None,
    channel: Optional[str] = None,
    path: Optional[str] = None,
    config: Optional[dict[str, str]] = None,
) -> None:
    # due to: https://github.com/juju/python-libjuju/issues/1057
    # the following call does not work:
    # application = ops_test.model.applications[APP_NAME]
    # await application.refresh(
    #     revision=rev,
    # )

    # Point to the right model, as we are calling the juju cli directly
    args = [f"--model={ops_test.model.info.name}"]
    if revision:
        args.append(f"--revision={revision}")
    if switch:
        args.append(f"--switch={switch}")
    if channel:
        args.append(f"--channel={channel}")
    if path:
        args.append(f"--path={path}")

    for attempt in Retrying(stop=stop_after_attempt(6), wait=wait_fixed(wait=30)):
        with attempt:
            cmd = ["juju", "refresh"]
            cmd.extend(args)
            cmd.append(app_name)
            if config:
                for key, val in config.items():
                    args.append(f"--config {key}={val}")

            subprocess.check_output(cmd)


async def assert_upgrade_to_local(
    ops_test: OpsTest, cwrites: ContinuousWrites, local_charm: str
) -> None:
    """Does the upgrade to local and asserts continuous writes."""
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

    async with ops_test.fast_forward():
        logger.info("Refresh the charm")
        await refresh(ops_test, app, path=local_charm, config={"profile": "testing"})

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
    await assert_continuous_writes_increasing(cwrites)
    await assert_continuous_writes_consistency(ops_test, cwrites, [app])
