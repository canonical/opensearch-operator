#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import os
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

from .helpers_deployments import wait_until
from .tls.helpers import TLS_CERTIFICATES_APP_NAME


@pytest.fixture(scope="module")
async def charm(ops_test: OpsTest):
    """Build the charm-under-test."""
    # Build charm from local source folder.
    yield await ops_test.build_charm(".")


@pytest.fixture()
async def self_signed_operator(ops_test: OpsTest) -> str:
    """Deploys and configures the self signed certificate."""
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="latest/edge", config=config)
    await wait_until(ops_test, apps=[TLS_CERTIFICATES_APP_NAME], apps_statuses=["active"])
    return TLS_CERTIFICATES_APP_NAME
