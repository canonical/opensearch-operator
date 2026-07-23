# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest
from _pytest.config.argparsing import Parser

from .helpers import Substrate

# Repo root directory
_REPO_ROOT_DIR = Path(__file__).parent.parent.resolve()


def pytest_addoption(parser: Parser):
    parser.addoption(
        "--substrate",
        action="store",
        help="Substrate to test, either vm or k8s",
        choices=("vm", "k8s"),
        default="vm",
    )


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
