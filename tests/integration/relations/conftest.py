#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import glob
import os
import pathlib
import shutil
from importlib import reload

import pytest
import pytest_operator
from pytest_operator.plugin import OpsTest


def should_rebuild_charm(target: pathlib.Path) -> bool:
    """Returns the latest change in the charm path.

    Compare it with the *.charm file, if source files were changed more recently,
    then rebuild the charm.
    """
    ignored_prefixes = [".", "_"]
    target_path = os.path.dirname(target)
    for root, dirs, files in os.walk(target_path):
        if any([p for p in ignored_prefixes if root.startswith(p)]):
            continue
        for f in files:
            if f.endswith(".charm") or any([p for p in ignored_prefixes if f.startswith(p)]):
                continue
            if os.path.getctime(target) < os.path.getctime(f):
                return True
    return False


async def _build(ops_test, charmpath):
    """Decides if we should rebuild the charm or not.

    If the charm is not built yet or the source files were changed more recently than .charm,
    then rebuild the charm.

    Besides that, the current DP workflow only checks for the actual charm. It disconsiders
    any other testing charms existing in the tests/ folder.
    """
    if (
        # This is a build process that should be only valid whenever we are not in CI
        ("CI" not in os.environ or os.environ["CI"] != "true")
        and (
            # Now, check for the .charm file and if we had any recent updates in the sources
            not glob.glob(f"{charmpath}/*.charm")
            or should_rebuild_charm(glob.glob(f"{charmpath}/*.charm")[0])
        )
    ):
        name = await reload(pytest_operator.plugin).OpsTest.build_charm(ops_test, charmpath)
        return name
    return await ops_test.build_charm(charmpath)


@pytest.fixture(scope="module")
def application_charm(ops_test: OpsTest):
    """Build the application charm."""
    shutil.copyfile(
        "./lib/charms/data_platform_libs/v0/data_interfaces.py",
        "./tests/integration/relations/opensearch_provider/application-charm/lib/charms/data_platform_libs/v0/data_interfaces.py",
    )
    test_charm_path = "./tests/integration/relations/opensearch_provider/application-charm"
    return asyncio.get_event_loop().run_until_complete(_build(ops_test, test_charm_path))


@pytest.fixture(scope="module")
def opensearch_charm(ops_test: OpsTest):
    """Build the opensearch charm as well."""
    return asyncio.get_event_loop().run_until_complete(_build(ops_test, "."))
