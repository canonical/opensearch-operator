#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import APP_NAME, get_application_unit_ids
from .continuous_writes import ContinuousWrites
from .helpers import ORIGINAL_RESTART_DELAY, app_name, update_restart_delay

logger = logging.getLogger(__name__)


@pytest.fixture(scope="function")
async def reset_restart_delay(ops_test: OpsTest):
    """Resets service file delay on all units."""
    yield
    app = (await app_name(ops_test)) or APP_NAME
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, ORIGINAL_RESTART_DELAY)


@pytest.fixture(scope="function")
async def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    app = (await app_name(ops_test)) or APP_NAME
    return ContinuousWrites(ops_test, app)


@pytest.fixture(scope="function")
async def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="function")
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    await c_writes.start(repl_on_all_nodes=True)
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")
