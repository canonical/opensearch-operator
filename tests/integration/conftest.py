# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
import os
from pathlib import Path

import pytest
import yaml

from tests.helpers import Substrate
from pytest_operator.plugin import OpsTest


TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"
TLS_STABLE_CHANNEL = "1/stable"


CONFIG = yaml.safe_load(Path("./machines/config.yaml").read_text())
ACTIONS = yaml.safe_load(Path("./machines/actions.yaml").read_text())

METADATA = yaml.safe_load(Path("./machines/metadata.yaml").read_text())
K8S_METADATA = yaml.safe_load(
    Path("./kubernetes/metadata.yaml").read_text()
)

APP_NAME = METADATA["name"]

SERIES = "jammy"
UNIT_IDS = [0, 1, 2]
IDLE_PERIOD = 75


CONFIG_OPTS = {"profile": "testing"}
CLIENT_CHARM = "client-charm"

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
def charm_resources(substrate: Substrate) -> dict[str, str]:
    """Resources to pass to `juju deploy` for the OpenSearch charm.

    Juju does not reliably auto-populate OCI image resources for locally packed charms in all
    environments. For the K8s substrate, explicitly provide the `opensearch-image` resource so the
    controller can fetch the image. The K8s workload image is published independently from the
    charm base variants, so we always use the upstream image declared in metadata.
    """
    if substrate != "k8s":
        return {}

    upstream = (
        (K8S_METADATA.get("resources") or {}).get("opensearch-image", {}).get("upstream-source")
    )
    if not upstream:
        raise RuntimeError(
            "K8s test charm metadata is missing resources.opensearch-image.upstream-source"
        )

    return {"opensearch-image": upstream}


@pytest.fixture(autouse=True)
async def deploy_client_charm(ops_test: OpsTest, substrate: Substrate):
    """Deploy the client charm."""
    if substrate == "k8s" and CLIENT_CHARM not in ops_test.model.applications:
        await ops_test.model.deploy(
            "./tests/charms/dummy-client-charm/dummy-client-charm_amd64.charm",
            CLIENT_CHARM,
        )
        await ops_test.model.wait_for_idle(apps=[CLIENT_CHARM])


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
def charm(ubuntu_base, opensearch_base_path, substrate) -> str:
    """Path to the charm file to use for testing."""
    # Return str instead of pathlib.Path since python-libjuju's model.deploy(), juju deploy, and
    # juju bundle files expect local charms to begin with `./` or `/` to distinguish them from
    # Charmhub charms.
    if substrate == "k8s":
        return str(opensearch_base_path / f"opensearch-k8s_ubuntu@{ubuntu_base}-amd64.charm")
    return str(opensearch_base_path / f"opensearch_ubuntu@{ubuntu_base}-amd64.charm")
