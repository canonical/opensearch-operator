#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from collections.abc import AsyncGenerator
from typing import Any

import pytest
from juju.model import Model
from pytest_operator.plugin import OpsTest

from ..helpers import MODEL_CONFIG

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
async def failover_model(
    ops_test: OpsTest,
) -> AsyncGenerator[Model, Any]:
    # deploy the failover model
    failover_model = await ops_test.track_model("failover", keep=ops_test.ModelKeep.NEVER)
    await failover_model.set_config(MODEL_CONFIG)
    logger.info(f"Created model {failover_model.name}")
    yield failover_model

    await ops_test.forget_model(alias="failover", timeout=5 * 60, allow_failure=True)


@pytest.fixture(scope="module")
async def data_model(
    ops_test: OpsTest,
) -> AsyncGenerator[Model, Any]:
    # deploy the data model
    data_model = await ops_test.track_model("data", keep=ops_test.ModelKeep.NEVER)
    await data_model.set_config(MODEL_CONFIG)
    logger.info(f"Created model {data_model.name}")
    yield data_model

    await ops_test.forget_model(alias="data", timeout=5 * 60, allow_failure=True)
