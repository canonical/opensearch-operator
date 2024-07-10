#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess

import pytest
import yaml
from charms.opensearch.v0.constants_charm import (
    OPENSEARCH_SNAP_REVISION,
    OpenSearchSystemUsers,
    TLSRelationMissing,
)
from pytest_operator.plugin import OpsTest

from .helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids,
    get_conf_as_dict,
    get_leader_unit_id,
    get_leader_unit_ip,
    get_secrets,
    http_request,
    run_action,
)
from .helpers_deployments import wait_until
from .tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


DEFAULT_NUM_UNITS = 2


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy a couple of OpenSearch units."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        my_charm,
        num_units=DEFAULT_NUM_UNITS,
        series=SERIES,
    )
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        wait_for_exact_units=DEFAULT_NUM_UNITS,
        apps_full_statuses={APP_NAME: {"blocked": [TLSRelationMissing]}},
    )
    assert len(ops_test.model.applications[APP_NAME].units) == DEFAULT_NUM_UNITS


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_actions_get_admin_password(ops_test: OpsTest) -> None:
    """Test the retrieval of admin secrets."""
    # 1. run the action prior to finishing the config of TLS
    result = await run_action(ops_test, 0, "get-password")
    assert result.status == "failed"

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config)
    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=DEFAULT_NUM_UNITS,
    )

    leader_ip = await get_leader_unit_ip(ops_test)
    test_url = f"https://{leader_ip}:9200/"

    # 2. run the action after finishing the config of TLS
    result = await get_secrets(ops_test)
    assert result.get("username") == "admin"
    assert result.get("password")
    assert result.get("ca-chain")

    # parse_output fields non-null + make http request success
    http_resp_code = await http_request(ops_test, "GET", test_url, resp_status_code=True)
    assert http_resp_code == 200

    # 3. test retrieving password from non-supported user
    result = await run_action(ops_test, 0, "get-password", {"username": "non-existent"})
    assert result.status == "failed"


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_actions_rotate_admin_password(ops_test: OpsTest) -> None:
    """Test the rotation and change of admin password."""
    leader_ip = await get_leader_unit_ip(ops_test)
    test_url = f"https://{leader_ip}:9200/"

    leader_id = await get_leader_unit_id(ops_test)
    non_leader_id = [
        unit_id for unit_id in get_application_unit_ids(ops_test) if unit_id != leader_id
    ][0]

    # 1. run the action on a non_leader unit.
    result = await run_action(ops_test, non_leader_id, "set-password")
    assert result.status == "failed"

    # 2. run the action with the wrong username
    result = await run_action(ops_test, leader_id, "set-password", {"username": "wrong-user"})
    assert result.status == "failed"

    # 3. change password and verify the new password works and old password not
    password0 = (await get_secrets(ops_test, leader_id))["password"]
    result = await run_action(ops_test, leader_id, "set-password", {"password": "new_pwd"})
    password1 = result.response.get("admin-password")
    assert password1
    assert password1 == (await get_secrets(ops_test, leader_id))["password"]

    http_resp_code = await http_request(ops_test, "GET", test_url, resp_status_code=True)
    assert http_resp_code == 200

    http_resp_code = await http_request(
        ops_test, "GET", test_url, resp_status_code=True, user_password=password0
    )
    assert http_resp_code == 401

    # 4. change password with auto-generated one
    result = await run_action(ops_test, leader_id, "set-password")
    password2 = result.response.get("admin-password")
    assert password2

    http_resp_code = await http_request(ops_test, "GET", test_url, resp_status_code=True)
    assert http_resp_code == 200

    http_resp_code = await http_request(
        ops_test, "GET", test_url, resp_status_code=True, user_password=password1
    )
    assert http_resp_code == 401


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.parametrize("user", [("monitor"), ("kibanaserver")])
async def test_actions_rotate_system_user_password(ops_test: OpsTest, user) -> None:
    """Test the rotation and change of admin password."""
    leader_ip = await get_leader_unit_ip(ops_test)
    test_url = f"https://{leader_ip}:9200/"

    leader_id = await get_leader_unit_id(ops_test)

    # run the action w/o password parameter
    password0 = (await get_secrets(ops_test, leader_id, user))["password"]
    result = await run_action(ops_test, leader_id, "set-password", {"username": user})
    password1 = result.response.get(f"{user}-password")
    assert password1 != password0

    # 1. change password with auto-generated one
    http_resp_code = await http_request(
        ops_test, "GET", test_url, resp_status_code=True, user=user, user_password=password1
    )
    assert http_resp_code == 200

    http_resp_code = await http_request(
        ops_test, "GET", test_url, resp_status_code=True, user=user, user_password=password0
    )
    assert http_resp_code == 401

    # 2. change password and verify the new password works and old password not
    password0 = (await get_secrets(ops_test, leader_id, user))["password"]
    result = await run_action(
        ops_test, leader_id, "set-password", {"username": user, "password": "new_pwd"}
    )
    password1 = result.response.get(f"{user}-password")
    assert password1
    assert password1 == (await get_secrets(ops_test, leader_id, user))["password"]

    http_resp_code = await http_request(
        ops_test, "GET", test_url, resp_status_code=True, user=user, user_password=password1
    )
    assert http_resp_code == 200

    http_resp_code = await http_request(
        ops_test, "GET", test_url, resp_status_code=True, user=user, user_password=password0
    )
    assert http_resp_code == 401


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_check_pinned_revision(ops_test: OpsTest) -> None:
    """Test check the pinned revision."""
    leader_id = await get_leader_unit_id(ops_test)

    installed_info = yaml.safe_load(
        subprocess.check_output(
            [
                "juju",
                "ssh",
                f"opensearch/{leader_id}",
                "--",
                "sudo",
                "snap",
                "info",
                "opensearch",
                "--color=never",
                "--unicode=always",
            ],
            text=True,
        ).replace("\r\n", "\n")
    )["installed"].split()
    logger.info(f"Installed snap: {installed_info}")
    assert installed_info[1] == f"({OPENSEARCH_SNAP_REVISION})"
    assert installed_info[3] == "held"


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_check_workload_version(ops_test: OpsTest) -> None:
    """Test to check if the workload_version file is updated."""
    leader_id = await get_leader_unit_id(ops_test)

    installed_info = yaml.safe_load(
        subprocess.check_output(
            [
                "juju",
                "ssh",
                f"opensearch/{leader_id}",
                "--",
                "sudo",
                "snap",
                "info",
                "opensearch",
                "--color=never",
                "--unicode=always",
            ],
            text=True,
        ).replace("\r\n", "\n")
    )["installed"].split()
    logger.info(f"Installed snap: {installed_info}")

    workload_version = None
    with open("./workload_version") as f:
        workload_version = f.read().rstrip("\n")
    assert installed_info[0] == workload_version


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_all_units_have_all_local_users(ops_test: OpsTest) -> None:
    """Compare the internal_users.yaml of all units."""
    # Get the leader's version of internal_users.yml
    leader_id = await get_leader_unit_id(ops_test)
    leader_name = f"{APP_NAME}/{leader_id}"
    filename = "/var/snap/opensearch/current/etc/opensearch/opensearch-security/internal_users.yml"
    leader_conf = get_conf_as_dict(ops_test, leader_name, filename)

    # Check on all units if they have the same
    for unit in ops_test.model.applications[APP_NAME].units:
        unit_conf = get_conf_as_dict(ops_test, unit.name, filename)
        for user in OpenSearchSystemUsers:
            assert leader_conf[user]["hash"] == unit_conf[user]["hash"]


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_all_units_have_internal_users_synced(ops_test: OpsTest) -> None:
    """Compare the internal_users.yaml of all units."""
    # Get the leader's version of internal_users.yml
    leader_id = await get_leader_unit_id(ops_test)
    leader_name = f"{APP_NAME}/{leader_id}"
    filename = "/var/snap/opensearch/current/etc/opensearch/opensearch-security/internal_users.yml"
    leader_conf = get_conf_as_dict(ops_test, leader_name, filename)

    # Check on all units if they have the same
    for unit in ops_test.model.applications[APP_NAME].units:
        unit_conf = get_conf_as_dict(ops_test, unit.name, filename)
        assert leader_conf == unit_conf


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_remove_application(ops_test: OpsTest) -> None:
    """Removes the application with a single unit."""
    ops_test.model.remove_application(APP_NAME, block_until_done=True)
