# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
from unittest.mock import PropertyMock

import pytest
from ops import JujuVersion
from pytest_mock import MockerFixture


@pytest.fixture
def only_with_juju_secrets(mocker: MockerFixture):
    """This fixture will force the usage of secrets whenever run on Juju 3.x."""
    mocker.patch.object(JujuVersion, "has_secrets", new_callable=PropertyMock).return_value = True
    return True
