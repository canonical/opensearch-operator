# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest


@pytest.fixture(autouse=True)
def with_juju_secrets(monkeypatch):
    monkeypatch.setattr("ops.JujuVersion.has_secrets", True)
