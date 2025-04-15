#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest


@pytest.fixture(scope="module")
async def application_charm() -> str:
    """Build the application charm."""
    return "./tests/integration/relations/opensearch_provider/application-charm/application_ubuntu@22.04-amd64.charm"
