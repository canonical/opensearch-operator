# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import pathlib
import subprocess
from asyncio import gather
from typing import Any, AsyncGenerator

import pytest
import requests
import yaml
from integration.helpers import CONFIG_OPTS, SERIES, get_leader_unit_ip
from juju.client.client import Action, ActionResult
from juju.controller import Controller
from juju.model import Model
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_delay, wait_fixed

IDENTITY_PLATFORM_NAME = "identity-platform"
DATA_INTEGRATOR_NAME = "data-integrator"
MICROK8S_CLOUD_NAME = "uk8s"

DATA_INTEGRATOR_CONFIG = {
    "index-name": "admin-index",
    "extra-user-roles": "admin",
}

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


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy(ops_test: OpsTest, opensearch_charm, microk8s_model: Model):
    await gather(
        ops_test.model.deploy(
            opensearch_charm,
            num_units=2,
            series=SERIES,
            config=CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            DATA_INTEGRATOR_NAME,
            config=DATA_INTEGRATOR_CONFIG,
        ),
        microk8s_model.deploy(
            IDENTITY_PLATFORM_NAME,
            channel="edge",
            trust=True,
        ),
    )
    await gather(ops_test.model.wait_for_idle(), microk8s_model.wait_for_idle())


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_setup_relations(ops_test: OpsTest, microk8s_model: Model):
    await microk8s_model.create_offer("certificates", "certificates", "self-signed-certificates")
    await ops_test.model.consume(f"admin/{microk8s_model.name}.certificates")
    await ops_test.model.integrate("opensearch:certificates", "certificates")

    await microk8s_model.create_offer("oauth", "oauth", "hydra")
    await ops_test.model.consume(f"admin/{microk8s_model.name}.oauth")
    await ops_test.model.integrate("opensearch:oauth", "oauth")

    await ops_test.model.integrate(
        "opensearch:opensearch-client", f"{DATA_INTEGRATOR_NAME}:opensearch"
    )

    await gather(ops_test.model.wait_for_idle(status="active"), microk8s_model.wait_for_idle())


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_setup_oauth(ops_test: OpsTest, microk8s_model: Model):
    action: Action = (
        await microk8s_model.applications["hydra"]
        .units[0]
        .run_action(
            "create-oauth-client",
            **{
                "scope": ["openid", "profile", "email", "phone", "offline"],
                "grant-types": ["client_credentials"],
                "audience": ["opensearch"],
            },
        )
    )
    await action.wait()
    global oauth_client_id
    oauth_client_id = action.results.get("client-id")
    oauth_client_secret = action.results.get("client-secret")
    assert (
        oauth_client_id and oauth_client_secret
    ), "failed to retrieve oauth client id and secret from hydra"

    action = (
        await microk8s_model.applications["traefik-public"]
        .units[0]
        .run_action("show-proxied-endpoints")
    )
    await action.wait()
    result = json.loads(action.results.get("proxied-endpoints", "{}"))
    hydra_url = result.get("hydra", {}).get("url")
    assert hydra_url, "failed to retrieve hydra url from traefik"

    result = requests.post(
        f"{hydra_url}/oauth2/token",
        {"scope": "openid", "grant_type": "client_credentials", "audience": "opensearch"},
        auth=requests.auth.HTTPBasicAuth(oauth_client_id, oauth_client_secret),
        verify=False,
    )
    global oauth_access_token
    oauth_access_token = result.json().get("access_token")
    assert oauth_access_token, "failed to retrieve access token from hydra"


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_oauth_access(ops_test: OpsTest, microk8s_model: Model):
    opensearch_address = await get_leader_unit_ip(ops_test, "opensearch")
    opensearch_url = f"https://{opensearch_address}:9200/_cat/indices"
    result = requests.get(
        opensearch_url, headers={"Authorization": f"Bearer {oauth_access_token}"}, verify=False
    )
    assert result.json().get("status") == 403, "no permissions error expected"

    action = (
        await ops_test.model.applications[DATA_INTEGRATOR_NAME]
        .units[0]
        .run_action("get-credentials")
    )
    await action.wait()
    data_integrator_user = action.results.get("opensearch", {}).get("username")
    assert data_integrator_user, "failed to retrieve data integrator user"

    config_without_roles = await ops_test.model.applications["opensearch"].get_config()
    config_with_roles = config_without_roles.copy()
    config_with_roles["roles_mapping"] = json.dumps({oauth_client_id: data_integrator_user})
    await ops_test.model.applications["opensearch"].set_config(config_with_roles)
    await ops_test.model.wait_for_idle(status="active")

    result = requests.get(
        opensearch_url, headers={"Authorization": f"Bearer {oauth_access_token}"}, verify=False
    )
    assert result.status_code == 200, "requst expected to succeed with roles mapping"

    await ops_test.model.applications["opensearch"].set_config(config_without_roles)
    await ops_test.model.wait_for_idle(status="active")

    result = requests.get(
        opensearch_url, headers={"Authorization": f"Bearer {oauth_access_token}"}, verify=False
    )
    assert result.json().get("status") == 403, "no permissions error expected"
