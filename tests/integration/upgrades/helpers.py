#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess
from typing import Optional

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_attempt, wait_fixed

from ..helpers import CONFIG_OPTS, run_action
from ..helpers_deployments import get_application_units, wait_until

OPENSEARCH_CHARM = "opensearch"
OPENSEARCH_CHANNEL = "2/edge"
PROFILES_REVISION = 185

TIMEOUT = 2400
IDLE_PERIOD = 30
FAST_INTERVAL = "60s"

VERSION_N_MINUS_2 = "2.17.0"
VERSION_N_MINUS_1 = "2.18.0"

VERSION_TO_REVISION = {
    VERSION_N_MINUS_2: {"jammy": 168, "noble": 206},
    VERSION_N_MINUS_1: {"jammy": 209, "noble": 208},
}

FROM_VERSION_PREFIX = "from_v{}_to_local"

UPGRADE_PARAMS = [
    pytest.param(
        version,
        id=FROM_VERSION_PREFIX.format(version),
        marks=pytest.mark.group(
            id="two_version_upgrade" if version == VERSION_N_MINUS_2 else "one_version_upgrade"
        ),
    )
    for version in VERSION_TO_REVISION.keys()
]

logger = logging.getLogger(__name__)


def testing_config_if_supported(revision: int) -> dict[str, str]:
    """Returns 'testing' profile config if given revision supports profiles"""
    return CONFIG_OPTS if revision >= PROFILES_REVISION else {}


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
    if config:
        for key, val in config.items():
            args.extend(["--config", f"{key}={val}"])

    for attempt in Retrying(stop=stop_after_attempt(6), wait=wait_fixed(wait=30)):
        with attempt:
            cmd = ["juju", "refresh"]
            cmd.append(app_name)
            cmd.extend(args)
            subprocess.check_output(cmd)


async def assert_upgrade_to_revision(
    ops_test: OpsTest,
    app: str,
    revision: int,
    config: dict[str, str] = {},
):
    """Upgrades app to revision"""
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    # run pre-upgrade-check action on leader
    action = await run_action(ops_test, leader_id, "pre-upgrade-check", app=app)
    logger.info(f"pre-upgrade-check: {action}")
    assert action.status == "completed"

    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        logger.info(f"Refreshing '{app}' to revision {revision}")
        await refresh(
            ops_test,
            app,
            revision=revision,
            config=testing_config_if_supported(revision) | config,
        )

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                app: len(units),
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        # run resume-upgrade action on leader
        action = await run_action(ops_test, leader_id, "resume-upgrade", app=app)
        logger.info(f"resume-upgrade: {action}")
        assert action.status == "completed"

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info(f"Upgrade of '{app}' completed")


async def assert_upgrade_to_local(
    ops_test: OpsTest, app: str, charm: str, config: dict[str, str] = {}
):
    """Upgrades to local charm"""
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    # run pre-upgrade-check action on leader
    action = await run_action(ops_test, leader_id, "pre-upgrade-check", app=app)
    logger.info(f"pre-upgrade-check: {action}")
    assert action.status == "completed"

    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        logger.info(f"Refreshing '{app}' local charm")
        await refresh(ops_test, app, path=charm, config=CONFIG_OPTS | config)

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                app: len(units),
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        # run resume-upgrade action on leader
        action = await run_action(ops_test, leader_id, "resume-upgrade", app=app)
        logger.info(f"resume-upgrade: {action}")
        assert action.status == "completed"

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info(f"Upgrade of '{app}' completed")


async def assert_rollback_to_revision(
    ops_test: OpsTest, app: str, charm: str, revision: int, config: dict[str, str] = {}
):
    """Upgrades to local charm and rolls back to revision mid-upgrade"""
    units = await get_application_units(ops_test, app)
    leader_id = [unit.id for unit in units if unit.is_leader][0]

    # run pre-upgrade-check action on leader
    action = await run_action(ops_test, leader_id, "pre-upgrade-check", app=app)
    logger.info(f"pre-upgrade-check: {action}")
    assert action.status == "completed"

    n_units = len(units)
    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        logger.info(f"Refreshing '{app}' to local charm")
        await refresh(ops_test, app, path=charm, config=CONFIG_OPTS | config)

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                app: n_units,
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        # switch to store charm
        await refresh(
            ops_test,
            app,
            switch=OPENSEARCH_CHARM,
            channel=OPENSEARCH_CHANNEL,
            config=CONFIG_OPTS | config,
        )

        # Wait until we are set in an idle state and can rollback the revision.
        # app status blocked: that will happen if we are jumping N-2 versions in our test
        # app status active: that will happen if we are jumping N-1 in our test
        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active", "blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                app: n_units,
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        logger.info(f"Rolling back '{app}' to revision: {revision}")
        await refresh(
            ops_test,
            app,
            revision=revision,
            config=testing_config_if_supported(revision) | config,
        )

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units={
                app: n_units,
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info(f"Rollback of '{app}' completed")
