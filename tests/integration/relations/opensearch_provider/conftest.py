#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from pytest_operator.plugin import OpsTest


@pytest.mark.abort_on_fail
@pytest.fixture(scope="module")
async def application_charm(ops_test: OpsTest):
    """Build the application charm."""
    test_charm_path = "./tests/integration/relations/opensearch_provider/application-charm"
    return await ops_test.build_charm(test_charm_path)


@pytest.mark.abort_on_fail
@pytest.fixture(scope="module")
async def opensearch_charm(ops_test: OpsTest):
    """Build the pgbouncer charm."""
    return await ops_test.build_charm(".")
