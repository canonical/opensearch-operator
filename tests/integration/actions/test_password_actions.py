#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_admin_secrets,
    get_application_unit_ids,
    get_leader_unit_id,
    http_request,
    run_action,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


@pytest.mark.actions_tests
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        my_charm,
        num_units=2,
        series=SERIES,
    )

    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="blocked", timeout=1000)
    assert len(ops_test.model.applications[APP_NAME].units) == 2


@pytest.mark.actions_tests
@pytest.mark.abort_on_fail
async def test_get_admin_password_action(ops_test: OpsTest) -> None:
    """Test the retrieval of admin secrets."""
    # 1. run the action prior to finishing the config of TLS
    result = await get_admin_secrets(ops_test)
    print(result)
    # expect error message

    # Deploy TLS Certificates operator.
    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="edge", config=config)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME], status="active", timeout=1000
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=2
    )

    # 2. run the action after finishing the config of TLS
    result = await get_admin_secrets(ops_test)
    assert result.get("username") == "admin"
    assert result.get("password")
    assert result.get("ca_chain")

    # parse_output fields non-null + make http request success
    http_resp_code = await http_request(ops_test, "GET", "/", resp_status_code=True)
    assert http_resp_code == 200

    # 3. test retrieving password from non-supported user
    result = await run_action(ops_test, 0, "get-password", {"username": "non-existent"})
    # expect failure


@pytest.mark.actions_tests
@pytest.mark.abort_on_fail
async def test_rotate_admin_password_action(ops_test: OpsTest) -> None:
    """Test the rotation and change of admin password."""
    leader_id = await get_leader_unit_id(ops_test)
    non_leader_id = [
        unit_id for unit_id in get_application_unit_ids(ops_test) if unit_id != leader_id
    ][0]

    # 1. run the action on a non_leader unit.
    result = await run_action(ops_test, non_leader_id, "set-password")
    # result fail

    # 2. run the action with the wrong username
    result = await run_action(ops_test, leader_id, "set-password", {"username": "wrong-user"})
    # result fail

    # 3. change password and verify the new password works and old password not
    password0 = (await get_admin_secrets(ops_test, leader_id))["password"]
    result = await run_action(ops_test, leader_id, "set-password", {"password": "new_pwd"})
    password1 = result.get("admin-password")
    assert password1
    assert password1 == (await get_admin_secrets(ops_test, leader_id))["password"]

    http_resp_code = await http_request(ops_test, "GET", "/", resp_status_code=True)
    assert http_resp_code == 200

    http_resp_code = await http_request(
        ops_test, "GET", "/", resp_status_code=True, user_password=password0
    )
    assert http_resp_code == 401

    # 4. change password with auto-generated one
    result = await run_action(ops_test, leader_id, "set-password")
    password2 = result.get("admin-password")
    assert password2

    http_resp_code = await http_request(ops_test, "GET", "/", resp_status_code=True)
    assert http_resp_code == 200

    http_resp_code = await http_request(
        ops_test, "GET", "/", resp_status_code=True, user_password=password1
    )
    assert http_resp_code == 401
