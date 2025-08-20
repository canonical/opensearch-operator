#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import pathlib
import subprocess
from typing import Any, AsyncGenerator

import pytest
import yaml
from juju.controller import Controller
from juju.model import Model
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

MICROK8S_CLOUD_NAME = "uk8s"


@pytest.fixture(scope="module")
async def application_charm() -> str:
    """Build the application charm."""
    return "./tests/integration/relations/opensearch_provider/application-charm/application_ubuntu@22.04-amd64.charm"


@pytest.fixture(scope="module")
async def microk8s_cloud(ops_test: OpsTest) -> AsyncGenerator[None, Any]:
    """Install and configure MicroK8s as second cloud on the same juju controller.

    Skips if it configured already. Automatically removes connection to the created
    cloud and removes MicroK8s from system unless keep models parameter is used.
    """
    controller_name = next(
        iter(yaml.safe_load(subprocess.check_output(["juju", "show-controller"])))
    )

    clouds = await ops_test._controller.clouds()
    if f"cloud-{MICROK8S_CLOUD_NAME}" in clouds.clouds:
        yield None
        return

    try:
        subprocess.run(["sudo", "snap", "install", "--classic", "microk8s"], check=True)
        subprocess.run(["sudo", "snap", "install", "--classic", "kubectl"], check=True)
        subprocess.run(["sudo", "microk8s", "enable", "dns"], check=True)
        subprocess.run(["sudo", "microk8s", "enable", "hostpath-storage"], check=True)
        subprocess.run(
            ["sudo", "microk8s", "enable", "metallb:10.64.140.43-10.64.140.49"],
            check=True,
        )

        # Configure kubectl now
        subprocess.run(["mkdir", "-p", str(pathlib.Path.home() / ".kube")], check=True)
        kubeconfig = subprocess.check_output(["sudo", "microk8s", "config"])
        with open(str(pathlib.Path.home() / ".kube" / "config"), "w") as f:
            f.write(kubeconfig.decode())
        for attempt in Retrying(stop=stop_after_delay(150), wait=wait_fixed(15)):
            with attempt:
                if (
                    len(
                        subprocess.check_output(
                            "kubectl get po -A  --field-selector=status.phase!=Running",
                            shell=True,
                            stderr=subprocess.DEVNULL,
                        ).decode()
                    )
                    != 0
                ):  # We got sth different from "No resources found." in stderr
                    raise Exception()

        # Add microk8s to the kubeconfig
        subprocess.run(
            [
                "juju",
                "add-k8s",
                MICROK8S_CLOUD_NAME,
                "--client",
                "--controller",
                controller_name,
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        pytest.exit(str(e))

    yield None

    if not ops_test.keep_model:
        subprocess.run(
            [
                "juju",
                "remove-cloud",
                "--client",
                "--controller",
                controller_name,
                MICROK8S_CLOUD_NAME,
            ],
            check=True,
        )
        subprocess.run(["sudo", "snap", "remove", "--purge", "microk8s"], check=True)
        subprocess.run(["sudo", "snap", "remove", "--purge", "kubectl"], check=True)


@pytest.fixture(scope="module")
async def microk8s_model(ops_test: OpsTest, microk8s_cloud: None) -> AsyncGenerator[Model, Any]:
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
