#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

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


@pytest.fixture(scope="function")
def c_writes(ops_test: OpsTest):
    """Starts continuous write operations and clears writes at the end of the test."""
    c_writes = ContinuousWrites(ops_test, APP_NAME)
    c_writes.start(repl_on_all_nodes=False)
    yield c_writes
    c_writes.clear_all()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="function")
def c_writes_balanced(ops_test: OpsTest):
    """Starts continuous write operations and clears writes at the end of the test."""
    c_writes = ContinuousWrites(ops_test, APP_NAME)
    c_writes.start(repl_on_all_nodes=True)
    yield c_writes
    c_writes.clear_all()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.fixture(scope="function")
async def c_writes_runner(ops_test: OpsTest, c_writes):
    """Starts continuous write operations and clears writes at the end of the test."""
    yield c_writes

    reachable_ip = random.choice(await get_reachable_unit_ips(ops_test))
    await http_request(ops_test, "GET", f"https://{reachable_ip}:9200/_cat/nodes", json_resp=False)
    await http_request(
        ops_test, "GET", f"https://{reachable_ip}:9200/_cat/shards", json_resp=False
    )


@pytest.fixture(scope="function")
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes_balanced):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    yield c_writes_balanced

    reachable_ip = random.choice(await get_reachable_unit_ips(ops_test))
    await http_request(ops_test, "GET", f"https://{reachable_ip}:9200/_cat/nodes", json_resp=False)
    await http_request(
        ops_test, "GET", f"https://{reachable_ip}:9200/_cat/shards", json_resp=False
    )
