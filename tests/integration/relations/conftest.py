#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import shutil

import pytest
from pytest_operator.plugin import OpsTest


@pytest.fixture(scope="module")
async def application_charm(ops_test: OpsTest):
    """Build the application charm."""
    shutil.copyfile(
        "./lib/charms/data_platform_libs/v0/data_interfaces.py",
        "./tests/integration/relations/opensearch_provider/application-charm/lib/charms/data_platform_libs/v0/data_interfaces.py",
    )
    test_charm_path = "./tests/integration/relations/opensearch_provider/application-charm"
    return await ops_test.build_charm(test_charm_path)


@pytest.fixture(scope="module")
async def opensearch_charm(ops_test: OpsTest):
    """Build the opensearch charm."""
    return await ops_test.build_charm(".")


@pytest.fixture(scope="module")
async def opensearch_dashboards_charm(ops_test: OpsTest):
    """Build the dashboards charm -- temporary, to be removed."""
    test_charm_path = "./tests/integration/relations/opensearch_provider/opensearch-dashboards-operator"
    return await ops_test.build_charm(test_charm_path)
