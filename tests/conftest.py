# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
from importlib.metadata import version
from unittest.mock import PropertyMock

import pytest
from ops import JujuVersion
from pytest_mock import MockerFixture


@pytest.fixture(autouse=True)
def juju_has_secrets(mocker: MockerFixture):
    """This fixture will force the usage of secrets whenever run on Juju 3.x.

    NOTE: This is needed, as normally JujuVersion is set to 0.0.0 in tests
    (i.e. not the real juju version)
    """
    if version("juju") < "3":
        mocker.patch.object(
            JujuVersion, "has_secrets", new_callable=PropertyMock
        ).return_value = False
        return False
    else:
        mocker.patch.object(
            JujuVersion, "has_secrets", new_callable=PropertyMock
        ).return_value = True
        return True


@pytest.fixture
def only_with_juju_secrets(juju_has_secrets):
    """Pretty way to skip Juju 3 tests."""
    if not juju_has_secrets:
        pytest.skip("Secrets test only applies on Juju 3.x")


@pytest.fixture
def only_without_juju_secrets(juju_has_secrets):
    """Pretty way to skip Juju 2-specific tests.

    Typically: to save CI time, when the same check were executed in a Juju 3-specific way already
    """
    if juju_has_secrets:
        pytest.skip("Skipping legacy secrets tests")
