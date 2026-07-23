#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import re
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml
from opensearch_single_kernel.common.constants import (
    OPENSEARCH_SNAP_REVISION,
)
from opensearch_single_kernel.common.statuses import GeneralStatuses, TlsStatuses
from pytest_operator.plugin import OpsTest

from tests.helpers import Substrate

from .conftest import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
    TLS_CERTIFICATES_APP_NAME,
    TLS_STABLE_CHANNEL,
)
from .continuous_writes import (
    ContinuousWrites,
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
)
from .helpers import (
    deploy_opensearch,
    get_application_unit_ids,
    get_conf_as_dict,
    get_leader_unit_id,
    get_leader_unit_ip,
    get_secrets,
    http_request,
    run_action,
)
from .helpers_deployments import wait_until

logger = logging.getLogger(__name__)

DEFAULT_NUM_UNITS = 2


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_and_remove_single_unit(
    charm, series, ops_test: OpsTest, substrate, charm_resources
) -> None:
    """Build and deploy OpenSearch with a single unit and remove it."""
    await ops_test.model.set_config(MODEL_CONFIG)

    await deploy_opensearch(
        ops_test,
        charm,
        substrate,
        APP_NAME,
        1,
        series=series,
        config=CONFIG_OPTS,
        resources=charm_resources,
    )
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
    )
    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        wait_for_exact_units=1,
        units_statuses={APP_NAME: [GeneralStatuses.ACTIVE_IDLE.value]},
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 1

    c_writes = ContinuousWrites(ops_test, APP_NAME)
    try:
        await c_writes.start()
        await assert_continuous_writes_increasing(c_writes)
        await assert_continuous_writes_consistency(ops_test, c_writes, [APP_NAME])

    finally:
        # Now, clean up
        await c_writes.stop()
        await ops_test.model.remove_application(APP_NAME, block_until_done=True)
        await ops_test.model.remove_application(TLS_CERTIFICATES_APP_NAME, block_until_done=True)


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    charm, series, ops_test: OpsTest, substrate, charm_resources
) -> None:
    """Build and deploy a couple of OpenSearch units."""
    model_config = MODEL_CONFIG
    model_config["update-status-hook-interval"] = "1m"

    await ops_test.model.set_config(MODEL_CONFIG)

    await deploy_opensearch(
        ops_test,
        charm,
        substrate,
        APP_NAME,
        DEFAULT_NUM_UNITS,
        series=series,
        config=CONFIG_OPTS,
        resources=charm_resources,
    )
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        wait_for_exact_units=DEFAULT_NUM_UNITS,
        apps_statuses={APP_NAME: [TlsStatuses.TLS_RELATION_MISSING.value]},
        units_statuses={APP_NAME: [TlsStatuses.TLS_RELATION_MISSING.value]},
    )
    assert len(ops_test.model.applications[APP_NAME].units) == DEFAULT_NUM_UNITS


@pytest.mark.abort_on_fail
async def test_actions_get_admin_password(ops_test: OpsTest, substrate) -> None:
    """Test the retrieval of admin secrets."""
    leader_id = await get_leader_unit_id(ops_test)

    # 1. run the action prior to finishing the config of TLS
    result = await run_action(ops_test, leader_id, "get-password")
    assert result.status == "failed"

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
    )
    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
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
    result = await run_action(ops_test, leader_id, "get-password", {"username": "non-existent"})
    assert result.status == "failed"


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
        ops_test,
        "GET",
        test_url,
        resp_status_code=True,
        user=user,
        user_password=password1,
    )
    assert http_resp_code == 200

    http_resp_code = await http_request(
        ops_test,
        "GET",
        test_url,
        resp_status_code=True,
        user=user,
        user_password=password0,
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
        ops_test,
        "GET",
        test_url,
        resp_status_code=True,
        user=user,
        user_password=password1,
    )
    assert http_resp_code == 200

    http_resp_code = await http_request(
        ops_test,
        "GET",
        test_url,
        resp_status_code=True,
        user=user,
        user_password=password0,
    )
    assert http_resp_code == 401


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("k8s")
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


@pytest.mark.abort_on_fail
async def test_check_workload_version(ops_test: OpsTest, substrate) -> None:
    """Test to check if the workload_version file is updated."""
    leader_id = await get_leader_unit_id(ops_test)

    command = [
        "juju",
        "ssh",
        "-m",
        ops_test.model.info.name,
        f"{APP_NAME}/{leader_id}",
        "--",
        "sudo",
        "opensearch.opensearch-bin",
        "--version",
    ]

    if substrate == "k8s":
        command = [
            "juju",
            "ssh",
            "-m",
            ops_test.model.info.name,
            "--container",
            "opensearch",
            f"{APP_NAME}/{leader_id}",
            "/usr/share/opensearch/bin/opensearch",
            "--version",
        ]

    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode:
        raise subprocess.CalledProcessError(proc.returncode, command, output=stdout, stderr=stderr)

    version_output = stdout.decode().replace("\r\n", "\n")
    version_match = re.search(r"Version:\s*([^,\s]+)", version_output)
    assert version_match, f"Unable to extract workload version from: {version_output}"
    installed_version = version_match.group(1)

    workload_version = None
    if substrate == "k8s":
        workload_version_path = "./kubernetes/workload_version"
    elif substrate == "vm":
        workload_version_path = "./machine/workload_version"
    workload_version = Path(workload_version_path).read_text().strip()
    assert installed_version == workload_version


@pytest.mark.abort_on_fail
async def test_all_units_have_internal_users_synced(
    ops_test: OpsTest, substrate: Substrate
) -> None:
    """Compare the internal_users.yaml of all units."""
    # Get the leader's version of internal_users.yml
    leader_id = await get_leader_unit_id(ops_test)
    leader_name = f"{APP_NAME}/{leader_id}"

    filename = (
        "/etc/opensearch/opensearch-security/internal_users.yml"
        if substrate == "k8s"
        else "/var/snap/opensearch/current/etc/opensearch/opensearch-security/internal_users.yml"
    )

    leader_conf = get_conf_as_dict(ops_test, leader_name, filename, substrate)

    # Check on all units if they have the same
    for unit in ops_test.model.applications[APP_NAME].units:
        unit_conf = get_conf_as_dict(ops_test, unit.name, filename, substrate)
        assert leader_conf == unit_conf


@pytest.mark.abort_on_fail
async def test_add_users_and_calling_update_status(ops_test: OpsTest) -> None:
    """Add users and call update status."""
    leader_id = await get_leader_unit_id(ops_test)
    leader_ip = await get_leader_unit_ip(ops_test)
    test_url = f"https://{leader_ip}:9200/_plugins/_security/api/internalusers/my_user"

    http_resp_code = await http_request(
        ops_test,
        "PUT",
        test_url,
        resp_status_code=True,
        payload={"hash": "1234"},
    )
    assert http_resp_code >= 200 and http_resp_code < 300

    cmd = '"export JUJU_DISPATCH_PATH=hooks/update-status; ./dispatch"'
    exec_cmd = f"juju exec -u opensearch/{leader_id} -m {ops_test.model.name} -- {cmd}"
    try:
        # The "normal" subprocess.run with "export ...; ..." cmd was failing
        # Noticed that, for this case, canonical/jhack uses shlex instead to split.
        # Adding it fixed the issue.
        subprocess.run(shlex.split(exec_cmd))
    except Exception as e:
        logger.error(
            f"Failed to apply state: process exited with {e.returncode}; "
            f"stdout = {e.stdout}; "
            f"stderr = {e.stderr}.",
        )
    await asyncio.sleep(300)
    http_resp_code = await http_request(ops_test, "GET", test_url, resp_status_code=True)
    assert http_resp_code >= 200 and http_resp_code < 300
