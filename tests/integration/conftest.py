# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import os
from pathlib import Path

import pytest
import yaml

TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"
TLS_STABLE_CHANNEL = "1/stable"


CONFIG = str(yaml.safe_load(Path("./config.yaml").read_text()))
ACTIONS = str(yaml.safe_load(Path("./actions.yaml").read_text()))
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())


APP_NAME = METADATA["name"]

SERIES = "jammy"
UNIT_IDS = [0, 1, 2]
IDLE_PERIOD = 75


CONFIG_OPTS = {"profile": "testing"}

MODEL_CONFIG = {
    "logging-config": "<root>=INFO;unit=DEBUG",
    "update-status-hook-interval": "5m",
    "cloudinit-userdata": """postruncmd:
        - [ 'sysctl', '-w', 'vm.max_map_count=262144' ]
        - [ 'sysctl', '-w', 'fs.file-max=1048576' ]
        - [ 'sysctl', '-w', 'vm.swappiness=0' ]
        - [ 'sysctl', '-w', 'net.ipv4.tcp_retries2=5' ]
    """,
}


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
