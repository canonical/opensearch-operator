# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import pathlib
import subprocess
from asyncio import gather
from typing import Any, AsyncGenerator

import pytest
import yaml
from integration.helpers import CONFIG_OPTS, SERIES
from juju.controller import Controller
from juju.model import Model
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

IDENTITY_PLATFORM_NAME = "identity-platform"
MICROK8S_CLOUD_NAME = "uk8s"

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
async def microk8s_cloud(ops_test: OpsTest) -> AsyncGenerator[None, Any]:
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
    model_name = f"{ops_test.model_name}-uk8s"
    controller = Controller()
    await controller.connect()
    model = await controller.add_model(model_name, cloud_name=MICROK8S_CLOUD_NAME)

    yield model

    await model.disconnect()
    if not ops_test.keep_model:
        await controller.destroy_model(model_name, destroy_storage=True, force=True)
        while model_name in await controller.list_models():
            await asyncio.sleep(5)
    await controller.disconnect()


@pytest.mark.abort_on_fail
async def test_deploy(ops_test: OpsTest, opensearch_charm, microk8s_model: Model):
    await ops_test.model.deploy(
        opensearch_charm,
        num_units=2,
        series=SERIES,
        config=CONFIG_OPTS,
    )
    await microk8s_model.deploy(
        IDENTITY_PLATFORM_NAME,
        channel="edge",
        trust=True,
    )
    await gather(ops_test.model.wait_for_idle(), microk8s_model.wait_for_idle())
