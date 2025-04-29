# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
from asyncio import gather

import pytest
import requests
from integration.helpers import CONFIG_OPTS, get_leader_unit_ip
from juju.client.client import Action
from juju.model import Model
from pytest_operator.plugin import OpsTest

IDENTITY_PLATFORM_NAME = "identity-platform"
DATA_INTEGRATOR_NAME = "data-integrator"
SECOND_DATA_INTEGRATOR_NAME = "second-data-integrator"

DATA_INTEGRATOR_CONFIG = {
    "index-name": "admin-index",
    "extra-user-roles": "admin",
}
SECOND_DATA_INTEGRATOR_CONFIG = {
    "index-name": "dev-index",
}

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy(ops_test: OpsTest, charm, series, microk8s_model: Model):
    """Deploy OpenSearch, data integrator and identity platform (K8s) simultaneously."""
    await gather(
        ops_test.model.deploy(
            charm,
            num_units=2,
            series=series,
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
    await gather(
        ops_test.model.wait_for_idle(timeout=1000), microk8s_model.wait_for_idle(timeout=1000)
    )


@pytest.mark.abort_on_fail
async def test_setup_relations(ops_test: OpsTest, microk8s_model: Model):
    """Establish all the required relations.

    Connects OpenSearch, data integrator and identity platform (cross-model).
    """
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


@pytest.mark.abort_on_fail
async def test_setup_oauth(ops_test: OpsTest, microk8s_model: Model):
    """Configure new OAuth client on Hydra (identity platform).

    Also, acquire corresponding access token for the further testing.
    """
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


@pytest.mark.abort_on_fail
async def test_oauth_access(ops_test: OpsTest, microk8s_model: Model):
    """Check access to the OpenSearch with an access token, acquired earlier.

    Ensure that roles mapping works correctly by elevating user
    to the admin role and checking access to the admin endpoint.
    """
    global opensearch_address
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

    global original_opensearch_config
    original_opensearch_config = await ops_test.model.applications["opensearch"].get_config()
    config_with_roles = original_opensearch_config.copy()
    config_with_roles["roles_mapping"] = json.dumps({oauth_client_id: data_integrator_user})
    await ops_test.model.applications["opensearch"].set_config(config_with_roles)
    await ops_test.model.wait_for_idle(status="active")

    result = requests.get(
        opensearch_url, headers={"Authorization": f"Bearer {oauth_access_token}"}, verify=False
    )
    assert result.status_code == 200, "request expected to succeed with roles mapping"


@pytest.mark.abort_on_fail
async def test_deploy_second_client(ops_test: OpsTest, microk8s_model: Model):
    """Deploy and configure second data integrator."""
    await ops_test.model.deploy(
        DATA_INTEGRATOR_NAME,
        application_name=SECOND_DATA_INTEGRATOR_NAME,
        config=SECOND_DATA_INTEGRATOR_CONFIG,
    )
    await ops_test.model.wait_for_idle()
    await ops_test.model.integrate(SECOND_DATA_INTEGRATOR_NAME, "opensearch")
    await ops_test.model.wait_for_idle()


@pytest.mark.abort_on_fail
async def test_oauth_access_second_client(ops_test: OpsTest, microk8s_model: Model):
    """Change roles mapping from first data integrator user to second one.

    Ensure, that admin permissions from the first one is removed, while role
    from the second one is added.
    """
    action = (
        await ops_test.model.applications[SECOND_DATA_INTEGRATOR_NAME]
        .units[0]
        .run_action("get-credentials")
    )
    await action.wait()
    second_data_integrator_user = action.results.get("opensearch", {}).get("username")
    assert second_data_integrator_user, "failed to retrieve second data integrator user"

    config_with_roles = original_opensearch_config.copy()
    config_with_roles["roles_mapping"] = json.dumps({oauth_client_id: second_data_integrator_user})
    await ops_test.model.applications["opensearch"].set_config(config_with_roles)
    await ops_test.model.wait_for_idle(status="active")

    # Ensure first data integrator admin role is removed
    result = requests.get(
        f"https://{opensearch_address}:9200/_cat/indices",
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert (
        result.json().get("status") == 403
    ), "no permissions error expected as admin role should be removed"

    # Ensure second data integrator role is configured
    result = requests.get(
        f"https://{opensearch_address}:9200/_plugins/_security/authinfo",
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.status_code == 200, "request for authinfo should success"
    assert sorted(result.json().get("roles")) == sorted(
        [
            "own_index",
            second_data_integrator_user,
        ]
    ), "second data integrator role should be enabled"


@pytest.mark.abort_on_fail
async def test_oauth_access_cleanup(ops_test: OpsTest, microk8s_model: Model):
    """Ensure that all of the oauth clients permissions are removed with clean roles mapping."""
    await ops_test.model.applications["opensearch"].set_config(original_opensearch_config)
    await ops_test.model.wait_for_idle(status="active")

    result = requests.get(
        f"https://{opensearch_address}:9200/_plugins/_security/authinfo",
        headers={"Authorization": f"Bearer {oauth_access_token}"},
        verify=False,
    )
    assert result.status_code == 200, "request for authinfo should success"
    assert result.json().get("roles") == ["own_index"], "all the mapped roles should be removed"
