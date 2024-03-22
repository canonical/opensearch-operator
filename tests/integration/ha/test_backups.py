#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for the OpenSearch charm with backups and restores.

This test suite will test backup and restore functionality of the OpenSearch charm
against every cloud provider currently supported. Tests are separated into groups
that falls in 2x categories:
* Per cloud provider tests: backup, restore, remove-readd relation and disaster recovery
* All cloud providers tests: build, deploy, test expected API errors and switch configs
                             between the clouds to ensure config changes are working as expected

The latter test group is called "all". The former is a set of groups, each corresponding to a
different cloud.
"""

import asyncio
import logging
import subprocess
import time
import uuid
from typing import Any, Dict

import boto3
import pytest
from charms.opensearch.v0.opensearch_backups import S3_REPOSITORY
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..ha.test_horizontal_scaling import IDLE_PERIOD
from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_leader_unit_id,
    get_leader_unit_ip,
    http_request,
    run_action,
)
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .helpers import (
    app_name,
    assert_continuous_writes_consistency,
    create_backup,
    delete_backup,
    list_backups,
    restore,
    start_and_check_continuous_writes,
)
from .helpers_data import index_docs_count

logger = logging.getLogger(__name__)

S3_INTEGRATOR = "s3-integrator"
S3_INTEGRATOR_CHANNEL = "latest/edge"
TIMEOUT = 10 * 60
BackupsPath = f"opensearch/{uuid.uuid4()}"


@pytest.fixture(scope="module")
def cloud_configs(
    github_secrets: Dict[str, str], microceph: Dict[str, str]
) -> Dict[str, Dict[str, str]]:
    # Figure out the address of the LXD host itself, where tests are executed
    # this is where microceph will be installed.
    ip = subprocess.check_output(["hostname", "-I"]).decode().split()[0]
    results = {
        "microceph": {
            "endpoint": f"http://{ip}",
            "bucket": microceph.bucket,
            "path": BackupsPath,
            "region": "default",
        },
    }
    if "AWS_ACCESS_KEY" in github_secrets:
        results["aws"] = {
            "endpoint": "https://s3.amazonaws.com",
            "bucket": "data-charms-testing",
            "path": BackupsPath,
            "region": "us-east-1",
        }
    return results


@pytest.fixture(scope="module")
def cloud_credentials(
    github_secrets: Dict[str, str], microceph: Dict[str, str]
) -> Dict[str, Dict[str, str]]:
    """Read cloud credentials."""
    results = {
        "microceph": {
            "access-key": microceph.access_key_id,
            "secret-key": microceph.secret_access_key,
        },
    }
    if "AWS_ACCESS_KEY" in github_secrets:
        results["aws"] = {
            "access-key": github_secrets["AWS_ACCESS_KEY"],
            "secret-key": github_secrets["AWS_SECRET_KEY"],
        }
    return results


async def _backup_docs_count(ops_test: OpsTest, app: str, unit_ip: str, backup_id: int) -> int:
    """Get the doc count of the index."""
    resp = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}/{backup_id}/_status",
        json_resp=True,
    )
    return {
        elem["snapshot"]: elem["indices"] for elem in resp["hits"]["total"]["value"]["snapshots"]
    }


@pytest.fixture(scope="module", autouse=True)
def remove_backups(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
):
    """Remove previously created backups from the cloud-corresponding bucket."""
    yield

    logger.info("Cleaning backups from cloud buckets")
    loop = asyncio.get_running_loop()
    leader_id_task = loop.create_task(get_leader_unit_id(ops_test))
    loop.run_until_complete(leader_id_task)
    leader_id = leader_id_task.result()

    list_backups_task = loop.create_task(run_action(ops_test, leader_id, "list-backups"))
    loop.run_until_complete(list_backups_task)
    backups = list_backups_task.result().response
    assert backups

    for backup in backups:
        loop.run_until_complete(delete_backup(ops_test, leader_id, backup["backup-id"]))

    for cloud_name, config in cloud_configs.items():
        if (
            cloud_name not in cloud_credentials
            or "access-key" not in cloud_credentials[cloud_name]
            or "secret-key" not in cloud_credentials[cloud_name]
        ):
            # This cloud has not been used in this test run
            continue

        session = boto3.session.Session(
            aws_access_key_id=cloud_credentials[cloud_name]["access-key"],
            aws_secret_access_key=cloud_credentials[cloud_name]["secret-key"],
            region_name=config["region"],
        )
        s3 = session.resource("s3", endpoint_url=config["endpoint"])
        bucket = s3.Bucket(config["bucket"])

        # Some of our runs target only a single cloud, therefore, they will
        # raise errors on the other cloud's bucket. We catch and log them.
        try:
            bucket.objects.filter(Prefix=f"{BackupsPath}/").delete()
        except Exception as e:
            logger.warning(f"Failed to clean up backups: {e}")


async def _configure_s3(
    ops_test: OpsTest, config: Dict[str, str], credentials: Dict[str, str], app_name: str
) -> None:
    await ops_test.model.applications[S3_INTEGRATOR].set_config(config)
    await run_action(
        ops_test,
        0,
        "sync-s3-credentials",
        params=credentials,
        app=S3_INTEGRATOR,
    )
    await ops_test.model.wait_for_idle(
        apps=[app_name, S3_INTEGRATOR],
        status="active",
        timeout=TIMEOUT,
    )


S3_INTEGRATOR = "s3-integrator"
S3_INTEGRATOR_CHANNEL = "latest/edge"
TIMEOUT = 10 * 60


@pytest.mark.parametrize(
    "cloud_name",
    [
        (pytest.param("microceph", marks=pytest.mark.group("microceph"))),
        (pytest.param("aws", marks=pytest.mark.group("aws"))),
    ],
)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, cloud_name: Dict[str, Dict[str, str]]) -> None:
    """Build and deploy an HA cluster of OpenSearch and corresponding S3 integration."""
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}

    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(S3_INTEGRATOR, channel=S3_INTEGRATOR_CHANNEL),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    # Credentials not set yet, this will move the opensearch to blocked state
    # Credentials are set per test scenario
    await ops_test.model.integrate(APP_NAME, S3_INTEGRATOR)


@pytest.mark.parametrize(
    "cloud_name",
    [
        (pytest.param("microceph", marks=pytest.mark.group("microceph"))),
        (pytest.param("aws", marks=pytest.mark.group("aws"))),
    ],
)
@pytest.mark.abort_on_fail
async def test_create_and_list_backups(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_writes_runner,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    cloud_name: str,
) -> None:
    """Runs the backup process whilst writing to the cluster into 'noisy-index'."""
    app = (await app_name(ops_test)) or APP_NAME
    leader_id = await get_leader_unit_id(ops_test)
    unit_ip = await get_leader_unit_ip(ops_test)
    config = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    logger.info("Creating backup")
    assert await create_backup(
        ops_test,
        leader_id,
        unit_ip=unit_ip,
    )
    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
    # Make sure we took a snapshot with data
    backups = await list_backups(ops_test, leader_id)
    for backup_id in backups.keys():
        assert (
            await _backup_docs_count(ops_test, app, unit_ip, backup_id)[
                ContinuousWrites.INDEX_NAME
            ]
            > 0
        )


@pytest.mark.parametrize(
    "cloud_name",
    [
        (pytest.param("microceph", marks=pytest.mark.group("microceph"))),
        (pytest.param("aws", marks=pytest.mark.group("aws"))),
    ],
)
@pytest.mark.abort_on_fail
async def test_restore(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    cloud_name: str,
) -> None:
    """Restores the cluster and tries to search for index."""
    unit_ip: str = await get_leader_unit_ip(ops_test)
    app: str = (await app_name(ops_test)) or APP_NAME
    leader_id: str = await get_leader_unit_id(ops_test)
    config: Dict[str, str] = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    backups: Dict[str, Any] = await list_backups(ops_test, leader_id)
    for backup_id in backups.keys():
        logger.info("Restoring backup")
        await restore(
            ops_test,
            backup_id,
            unit_ip,
            leader_id,
        )
        # Ensure we have the number of docs correctly restored
        assert await _backup_docs_count(ops_test, app, unit_ip, backup_id)[
            ContinuousWrites.INDEX_NAME
        ] == index_docs_count(
            ops_test,
            app,
            unit_ip,
            ContinuousWrites.INDEX_NAME,
        )

    # restart the continuous writes and check the cluster is still accessible post restore
    assert await start_and_check_continuous_writes(ops_test, unit_ip, app)


@pytest.mark.parametrize(
    "cloud_name",
    [
        (pytest.param("microceph", marks=pytest.mark.group("microceph"))),
        (pytest.param("aws", marks=pytest.mark.group("aws"))),
    ],
)
@pytest.mark.abort_on_fail
async def test_remove_and_readd_s3_relation(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_writes_runner,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    cloud_name: str,
) -> None:
    """Removes and re-adds the s3-credentials relation to test backup and restore."""
    app: str = (await app_name(ops_test)) or APP_NAME
    leader_id: str = await get_leader_unit_id(ops_test)
    unit_ip: str = await get_leader_unit_ip(ops_test)
    config: Dict[str, str] = cloud_configs[cloud_name]

    logger.info("Remove s3-credentials relation")
    # Remove relation
    await ops_test.model.applications[app].destroy_relation(
        "s3-credentials", f"{S3_INTEGRATOR}:s3-credentials"
    )
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    logger.info("Re-add s3-credentials relation")
    await ops_test.model.integrate(APP_NAME, S3_INTEGRATOR)
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    logger.info("Creating backup")
    assert await create_backup(
        ops_test,
        leader_id,
        unit_ip=unit_ip,
    )
    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)

    # Now, try a recovery
    backups = await list_backups(ops_test, leader_id)
    for backup_id in backups.keys():
        logger.info("Restoring backup")
        await restore(
            ops_test,
            backup_id,
            unit_ip,
            leader_id,
        )
        # Ensure we have the number of docs correctly restored
        assert await _backup_docs_count(ops_test, app, unit_ip, backup_id)[
            ContinuousWrites.INDEX_NAME
        ] == index_docs_count(
            ops_test,
            app,
            unit_ip,
            ContinuousWrites.INDEX_NAME,
        )
    # restart the continuous writes and check the cluster is still accessible post restore
    assert await start_and_check_continuous_writes(ops_test, unit_ip, app)


@pytest.mark.parametrize(
    "cloud_name",
    [
        (pytest.param("microceph", marks=pytest.mark.group("microceph"))),
        (pytest.param("aws", marks=pytest.mark.group("aws"))),
    ],
)
@pytest.mark.abort_on_fail
async def test_restore_to_new_cluster(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
    cloud_name: str,
) -> None:
    """Deletes the entire OpenSearch cluster and redeploys from scratch.

    Restores the backup and then checks if the same TEST_BACKUP_INDEX is there.
    """
    app: str = (await app_name(ops_test)) or APP_NAME

    logging.info("Destroying the application")
    await ops_test.model.remove_application(app, block_until_done=True)
    app_num_units: int = 3
    my_charm = await ops_test.build_charm(".")
    config: Dict[str, str] = cloud_configs[cloud_name]

    # Redeploy
    await asyncio.gather(
        ops_test.model.deploy(my_charm, num_units=app_num_units, series=SERIES),
    )
    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(APP_NAME, S3_INTEGRATOR)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    leader_id = await get_leader_unit_id(ops_test)
    unit_ip = await get_leader_unit_ip(ops_test)

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    backups = await list_backups(ops_test, leader_id)
    for backup_id in backups.keys():
        logger.info("Restoring backup")
        await restore(
            ops_test,
            backup_id,
            unit_ip,
            leader_id,
        )
        # Ensure we have the number of docs correctly restored
        assert await _backup_docs_count(ops_test, app, unit_ip, backup_id)[
            ContinuousWrites.INDEX_NAME
        ] == index_docs_count(
            ops_test,
            app,
            unit_ip,
            ContinuousWrites.INDEX_NAME,
        )
    # restart the continuous writes and check the cluster is still accessible post restore
    assert await start_and_check_continuous_writes(ops_test, unit_ip, app)


# -------------------------------------------------------------------------------------------
# Tests for the "all" group
#
# This group will iterate over each cloud, update its credentials via config and rerun
# the backup and restore tests.
# -------------------------------------------------------------------------------------------


@pytest.mark.group("all")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_deploy_and_test_status(ops_test: OpsTest) -> None:
    """Build, deploy and test status of an HA cluster of OpenSearch and corresponding backups.

    This test group will iterate over each cloud, update its credentials via config and rerun
    the backup and restore tests.
    """
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(S3_INTEGRATOR, channel=S3_INTEGRATOR_CHANNEL),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    # Credentials not set yet, this will move the opensearch to blocked state
    # Credentials are set per test scenario
    await ops_test.model.integrate(APP_NAME, S3_INTEGRATOR)


@pytest.mark.group("all")
@pytest.mark.abort_on_fail
async def test_repo_missing_message(ops_test: OpsTest) -> None:
    """Check the repo is missing."""
    unit_ip = await get_leader_unit_ip(ops_test)
    resp = await http_request(
        ops_test, "GET", f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}", json_resp=True
    )
    logger.info(f"Response: {resp}")
    assert resp["status"] == 404
    assert "repository_missing_exception" in resp["error"]["type"]


@pytest.mark.group("all")
@pytest.mark.abort_on_fail
async def test_wrong_s3_credentials(ops_test: OpsTest) -> None:
    """Check the repo is misconfigured."""
    unit_ip = await get_leader_unit_ip(ops_test)
    app = (await app_name(ops_test)) or APP_NAME

    config = {
        "endpoint": "http://localhost",
        "bucket": "error",
        "path": "/",
        "region": "default",
    }
    credentials = {
        "access-key": "error",
        "secret-key": "error",
    }

    # Not using _configure_s3 as this method will cause opensearch to block
    await ops_test.model.applications[S3_INTEGRATOR].set_config(config)
    await run_action(
        ops_test,
        0,
        "sync-s3-credentials",
        params=credentials,
        app=S3_INTEGRATOR,
    )
    await ops_test.model.wait_for_idle(
        apps=[app, S3_INTEGRATOR],
        status="active",
        timeout=TIMEOUT,
    )

    resp = await http_request(
        ops_test, "GET", f"https://{unit_ip}:9200/_snapshot/{S3_REPOSITORY}/_all", json_resp=True
    )
    logger.info(f"Response: {resp}")
    assert resp["status"] == 500
    assert "repository_exception" in resp["error"]["type"]
    assert "Could not determine repository generation from root blobs" in resp["error"]["reason"]


@pytest.mark.group("all")
@pytest.mark.abort_on_fail
async def test_change_config_and_backup_restore(
    ops_test: OpsTest,
    cloud_configs: Dict[str, Dict[str, str]],
    cloud_credentials: Dict[str, Dict[str, str]],
) -> None:
    """Run for each cloud and update the cluster config."""
    unit_ip: str = await get_leader_unit_ip(ops_test)
    app: str = (await app_name(ops_test)) or APP_NAME
    leader_id: str = await get_leader_unit_id(ops_test)

    initial_count: int = 0
    for cloud_name in cloud_configs.keys():
        logger.info(
            f"Index {ContinuousWrites.INDEX_NAME} has {initial_count} documents, starting there"
        )
        # Start the ContinuousWrites here instead of bringing as a fixture because we want to do
        # it for every cloud config we have and we have to stop it before restore, right down.
        writer: ContinuousWrites = ContinuousWrites(ops_test, app, initial_count=initial_count)
        await writer.start()
        time.sleep(10)

        logger.info(f"Syncing credentials for {cloud_name}")
        config: Dict[str, str] = cloud_configs[cloud_name]
        await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

        logger.info("Creating backup")
        assert await create_backup(
            ops_test,
            leader_id,
            unit_ip=unit_ip,
        )

        # Stop the continuous writes for the restore
        result: Any = await writer.stop()
        assert result.count > initial_count

        logger.info("Restoring backup")
        backups: Dict[int, str] = await list_backups(ops_test, leader_id)
        for backup_id in backups.keys():
            logger.info("Restoring backup")
            await restore(
                ops_test,
                backup_id,
                unit_ip,
                leader_id,
            )
            # Ensure we have the number of docs correctly restored
            assert await _backup_docs_count(ops_test, app, unit_ip, backup_id)[
                ContinuousWrites.INDEX_NAME
            ] == index_docs_count(
                ops_test,
                app,
                unit_ip,
                ContinuousWrites.INDEX_NAME,
            )
        # restart the continuous writes and check the cluster is still accessible post restore
        assert await start_and_check_continuous_writes(ops_test, unit_ip, app)
