#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import random

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import (
    APP_NAME,
    get_application_unit_ids,
    get_reachable_unit_ips,
    http_request,
)
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


async def _async_c_writes_start(ops_test: OpsTest, repl_on_all_nodes: bool = False):
    """Starts continuous write operations."""
    app = await app_name(ops_test) or APP_NAME
    c_writes = ContinuousWrites(ops_test, app)
    await c_writes.start(repl_on_all_nodes=repl_on_all_nodes)
    return c_writes


@pytest.fixture(scope="function")
def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    loop = asyncio.get_event_loop()
    c_writes = loop.run_until_complete(loop.create_task(_async_c_writes_start(ops_test, False)))
    yield c_writes
    loop.run_until_complete(loop.create_task(c_writes.clear()))
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="function")
def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    yield c_writes

    async def _finish_runner():
        reachable_ip = random.choice(await get_reachable_unit_ips(ops_test))
        await http_request(
            ops_test, "GET", f"https://{reachable_ip}:9200/_cat/nodes", json_resp=False
        )
        await http_request(
            ops_test, "GET", f"https://{reachable_ip}:9200/_cat/shards", json_resp=False
        )

    loop = asyncio.get_event_loop()
    loop.run_until_complete(loop.create_task(_finish_runner()))


@pytest.fixture(scope="function")
def c_writes_balanced(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    loop = asyncio.get_event_loop()
    c_writes_balanced = loop.run_until_complete(
        loop.create_task(_async_c_writes_start(ops_test, True))
    )
    yield c_writes_balanced
    loop.run_until_complete(loop.create_task(c_writes_balanced.clear()))
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="function")
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes_balanced):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    yield c_writes_balanced

    async def _finish_runner():
        reachable_ip = random.choice(await get_reachable_unit_ips(ops_test))
        await http_request(
            ops_test, "GET", f"https://{reachable_ip}:9200/_cat/nodes", json_resp=False
        )
        await http_request(
            ops_test, "GET", f"https://{reachable_ip}:9200/_cat/shards", json_resp=False
        )

    loop = asyncio.get_event_loop()
    loop.run_until_complete(loop.create_task(_finish_runner()))
