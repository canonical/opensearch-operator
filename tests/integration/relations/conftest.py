#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import shutil

import pytest
from pytest_operator.plugin import OpsTest


@pytest.fixture(scope="module")
def application_charm(ops_test: OpsTest):
    """Build the application charm."""
    shutil.copyfile(
        "./lib/charms/data_platform_libs/v0/data_interfaces.py",
        "./tests/integration/relations/opensearch_provider/application-charm/lib/charms/data_platform_libs/v0/data_interfaces.py",
    )
    test_charm_path = "./tests/integration/relations/opensearch_provider/application-charm"

    async def _build():
        return await ops_test.build_charm(test_charm_path)

    return asyncio.get_event_loop().run_until_complete(_build())


@pytest.fixture(scope="module")
def opensearch_charm(ops_test: OpsTest):
    """Build the opensearch charm."""

    async def _build():
        return await ops_test.build_charm(".")

    return asyncio.get_event_loop().run_until_complete(_build())
