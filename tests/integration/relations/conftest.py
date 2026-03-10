#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
from asyncio import sleep
from typing import Any, AsyncGenerator

import pytest
from juju.controller import Controller
from juju.model import Model
from pytest_operator.plugin import OpsTest

MICROK8S_CLOUD_NAME = "uk8s"


@pytest.fixture(scope="module")
async def ops_test_microk8s(
    request, tmp_path_factory, ops_test: OpsTest
) -> AsyncGenerator[OpsTest, Any]:
    """Create second OpsTest object, that is connected to the MicroK8s cloud.

    Automatically creates and destroys (unless keep models parameter is used)
    corresponding Juju model. MicroK8s and uk8s cloud are set up by spread prepare
    for OAuth tests.

    Returns:
        OpsTest object with MicroK8s connection and Juju model.
    """
    model_name = f"{ops_test.model_name}-uk8s"
    request.config.option.controller = ops_test.controller_name
    request.config.option.cloud = "uk8s"
    request.config.option.model = model_name
    request.config.option.model_alias = model_name
    ops_res = OpsTest(request, tmp_path_factory)
    await ops_res._setup_model()
    yield ops_res
    if not ops_test.keep_model:
        await ops_res.forget_model(alias=model_name)
        await ops_res._controller.destroy_model(model_name, destroy_storage=True, force=True)
        while model_name in await ops_res._controller.list_models():
            await sleep(5)
    await ops_res._cleanup_models()


@pytest.fixture(scope="module")
async def application_charm() -> str:
    """Build the application charm."""
    return "./tests/integration/relations/opensearch_provider/application-charm/application_ubuntu@22.04-amd64.charm"


@pytest.fixture(scope="module")
async def microk8s_model(ops_test: OpsTest) -> AsyncGenerator[Model, Any]:
    """Create new Juju model on the connected MicroK8s cloud.

    Automatically destroys that model unless keep models parameter is used.

    Returns:
        Connected Juju model.
    """
    model_name = f"{ops_test.model_name}-uk8s"
    controller = Controller()
    await controller.connect()
    if model_name in await controller.list_models():
        model = await controller.get_model(model_name)
    else:
        model = await controller.add_model(model_name, cloud_name=MICROK8S_CLOUD_NAME)

    yield model

    await model.disconnect()
    if not ops_test.keep_model:
        await controller.destroy_model(model_name, destroy_storage=True, force=True)
        while model_name in await controller.list_models():
            await asyncio.sleep(5)
    await controller.disconnect()
