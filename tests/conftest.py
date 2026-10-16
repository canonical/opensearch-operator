# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest
from _pytest.config.argparsing import Parser

from .helpers import Substrate

# Repo root directory
_REPO_ROOT_DIR = Path(__file__).parent.parent.resolve()


@pytest.fixture(scope="session")
def machine_platform() -> str:
    """Get the machine platform running the tests."""
    import platform

    return platform.machine()


@pytest.fixture(scope="session")
def architecture(machine_platform) -> str:
    """Get the architecture of the machine running the tests."""
    if machine_platform == "x86_64":
        return "amd64"
    elif machine_platform == "aarch64":
        return "arm64"
    else:
        raise ValueError(f"Unsupported machine platform: {machine_platform}")


def pytest_addoption(parser: Parser):
    parser.addoption(
        "--substrate",
        action="store",
        help="Substrate to test, either vm or k8s",
        choices=("vm", "k8s"),
        default="vm",
    )

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "skip_if_substrate(substrate): skip test for the given substrate"
    )

@pytest.fixture(autouse=True)
def skip_for_substrate(request, substrate: Substrate):
    if mark := request.node.get_closest_marker("skip_if_substrate"):
        if mark.args[0] == substrate:
            pytest.skip(f"This test does not run on {substrate}")


@pytest.fixture(scope="session")
def substrate(request) -> Substrate:
    """The substrate that we are testing."""
    return request.config.option.substrate


@pytest.fixture
def opensearch_base_path(substrate) -> Path:
    """The base path for the files of the opensearch charms, according to the substrate."""
    if substrate == "vm":
        return _REPO_ROOT_DIR / "machine"
    else:
        return _REPO_ROOT_DIR / "kubernetes"
