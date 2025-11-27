# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import os

import pytest


@pytest.fixture
def ubuntu_base():
    """Charm base version to use for testing."""
    return os.environ["CHARM_UBUNTU_BASE"]


@pytest.fixture
def series(ubuntu_base):
    """Workaround: python-libjuju does not support deploy base="ubuntu@22.04"; use series"""
    if ubuntu_base == "22.04":
        return "jammy"
    elif ubuntu_base == "24.04":
        return "noble"
    else:
        raise NotImplementedError


@pytest.fixture
def charm(ubuntu_base):
    """Path to the charm file to use for testing."""
    # Return str instead of pathlib.Path since python-libjuju's model.deploy(), juju deploy, and
    # juju bundle files expect local charms to begin with `./` or `/` to distinguish them from
    # Charmhub charms.
    return f"./opensearch_ubuntu@{ubuntu_base}-amd64.charm"


# workaround for https://bugs.launchpad.net/snapd/+bug/2127244
@pytest.fixture(autouse=True)
async def fix_ubuntu_22_image(ops_test, ubuntu_base: str):
    """Ensure that Ubuntu 22.04 uses the daily image stream to avoid image resolution issues."""
    if ubuntu_base == "22.04":
        await ops_test.model.set_config({"image-stream": "daily"})
