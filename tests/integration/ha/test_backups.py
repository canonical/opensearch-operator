#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import subprocess
import time
import uuid
from pathlib import Path

import boto3
import pytest
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..ha.test_horizontal_scaling import IDLE_PERIOD
from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_leader_unit_id,
    get_leader_unit_ip,
    run_action,
)
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .helpers import (
    app_name,
    assert_continuous_writes_consistency,
    backup_cluster,
    restore_cluster,
    start_and_check_continuous_writes,
)
from .helpers_data import index_docs_count

logger = logging.getLogger(__name__)


backups_by_cloud = {}
value_before_backup, value_after_backup = None, None


@pytest.fixture(scope="session")
def cloud_configs(github_secrets, microceph):
    # Add UUID to path to avoid conflict with tests running in parallel (e.g. multiple Juju
    # versions on a PR, multiple PRs)
    path = f"opensearch/{uuid.uuid4()}"

    ip = subprocess.check_output(["hostname", "-I"]).decode().split()[0]
    results = {
        "microceph": {
            "endpoint": f"http://{ip}",
            "bucket": microceph.bucket,
            "path": path,
            "region": "default",
        },
    }
    if "AWS_ACCESS_KEY" in github_secrets:
        results["aws"] = {
            "endpoint": "https://s3.amazonaws.com",
            "bucket": "data-charms-testing",
            "path": path,
            "region": "us-east-1",
        }
    return results


@pytest.fixture(scope="session")
def cloud_credentials(github_secrets, microceph) -> dict[str, dict[str, str]]:
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


@pytest.fixture(scope="session", autouse=True)
def clean_backups_from_buckets(github_secrets, cloud_configs, cloud_credentials) -> None:
    """Teardown to clean up created backups from clouds."""
    yield

    creds = cloud_credentials.copy()
    logger.info("Cleaning backups from cloud buckets")
    for cloud_name, config in cloud_configs.items():
        backup = backups_by_cloud.get(cloud_name)

        if not backup:
            continue

        session = boto3.session.Session(
            aws_access_key_id=creds[cloud_name]["access-key"],
            aws_secret_access_key=creds[cloud_name]["secret-key"],
            region_name=config["region"],
        )
        s3 = session.resource("s3", endpoint_url=config["endpoint"])
        bucket = s3.Bucket(config["bucket"])

        for f in backups_by_cloud[cloud_name]:
            backup_path = str(Path(config["path"]) / Path(str(f)))
            for bucket_object in bucket.objects.filter(Prefix=backup_path):
                bucket_object.delete()


async def _configure_s3(ops_test, config, credentials, app_name):
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
async def test_build_and_deploy(ops_test: OpsTest, cloud_name) -> None:
    """Build and deploy an HA cluster of OpenSearch and corresponding S3 integration."""
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),

    s3_charm = S3_INTEGRATOR
    # Convert to integer as environ always returns string
    app_num_units = 3
    await asyncio.gather(
        ops_test.model.deploy(s3_charm, channel=S3_INTEGRATOR_CHANNEL),
        ops_test.model.deploy(my_charm, num_units=app_num_units, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(APP_NAME, S3_INTEGRATOR)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )


@pytest.mark.parametrize(
    "cloud_name",
    [
        (pytest.param("microceph", marks=pytest.mark.group("microceph"))),
        (pytest.param("aws", marks=pytest.mark.group("aws"))),
    ],
)
@pytest.mark.abort_on_fail
async def test_backup_cluster(
    ops_test: OpsTest,
    c_writes: ContinuousWrites,
    c_writes_runner,
    cloud_configs,
    cloud_credentials,
    cloud_name,
) -> None:
    """Runs the backup process whilst writing to the cluster into 'noisy-index'."""
    app = (await app_name(ops_test)) or APP_NAME
    leader_id = await get_leader_unit_id(ops_test)
    unit_ip = await get_leader_unit_ip(ops_test)
    config = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    logger.info("Creating backup")
    backup_id = await backup_cluster(
        ops_test,
        leader_id,
    )
    assert backup_id > 0
    if cloud_name not in backups_by_cloud:
        backups_by_cloud[cloud_name] = []
    backups_by_cloud[cloud_name].append(backup_id)

    # Comparing the number of docs without stopping c_writes
    initial_count = await index_docs_count(ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME)
    time.sleep(5)
    count = await index_docs_count(ops_test, app, unit_ip, ContinuousWrites.INDEX_NAME)
    assert count > initial_count

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.parametrize(
    "cloud_name",
    [
        (pytest.param("microceph", marks=pytest.mark.group("microceph"))),
        (pytest.param("aws", marks=pytest.mark.group("aws"))),
    ],
)
@pytest.mark.abort_on_fail
async def test_restore_cluster(
    ops_test: OpsTest, cloud_configs, cloud_credentials, cloud_name
) -> None:
    """Restores the cluster and tries to search for index."""
    unit_ip = await get_leader_unit_ip(ops_test)
    app = (await app_name(ops_test)) or APP_NAME
    leader_id = await get_leader_unit_id(ops_test)
    config = cloud_configs[cloud_name]

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    logger.info("Restoring backup")
    assert await restore_cluster(
        ops_test,
        1,  # backup_id
        unit_ip,
        leader_id,
    )
    assert await start_and_check_continuous_writes(ops_test, unit_ip, app)


@pytest.mark.parametrize(
    "cloud_name",
    [
        (pytest.param("microceph", marks=pytest.mark.group("microceph"))),
        (pytest.param("aws", marks=pytest.mark.group("aws"))),
    ],
)
@pytest.mark.abort_on_fail
async def test_restore_cluster_after_app_destroyed(
    ops_test: OpsTest, cloud_configs, cloud_credentials, cloud_name
) -> None:
    """Deletes the entire OpenSearch cluster and redeploys from scratch.

    Restores the backup and then checks if the same TEST_BACKUP_INDEX is there.
    """
    app = (await app_name(ops_test)) or APP_NAME

    logging.info("Destroying the application")
    await ops_test.model.remove_application(app, block_until_done=True)
    app_num_units = 3
    my_charm = await ops_test.build_charm(".")
    config = cloud_configs[cloud_name]

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
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    logger.info(f"Syncing credentials for {cloud_name}")
    await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

    logger.info("Restoring backup")
    assert await restore_cluster(
        ops_test,
        1,  # backup_id
        leader_unit_ip,
        leader_id,
    )

    logger.info("Creating backup")
    backup_id = await backup_cluster(
        ops_test,
        leader_id,
    )
    assert backup_id > 0
    if cloud_name not in backups_by_cloud:
        backups_by_cloud[cloud_name] = []
    backups_by_cloud[cloud_name].append(backup_id)
    assert await start_and_check_continuous_writes(ops_test, leader_unit_ip, app)


@pytest.mark.parametrize(
    "cloud_name",
    [
        (pytest.param("microceph", marks=pytest.mark.group("microceph"))),
        (pytest.param("aws", marks=pytest.mark.group("aws"))),
    ],
)
@pytest.mark.abort_on_fail
async def test_remove_and_readd_s3_relation(
    ops_test: OpsTest, cloud_configs, cloud_credentials, cloud_name
) -> None:
    """Removes and re-adds the s3-credentials relation to test backup and restore."""
    app = (await app_name(ops_test)) or APP_NAME
    leader_id = await get_leader_unit_id(ops_test)
    unit_ip = await get_leader_unit_ip(ops_test)
    config = cloud_configs[cloud_name]

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
    backup_id = await backup_cluster(
        ops_test,
        leader_id,
    )
    assert backup_id > 0
    if cloud_name not in backups_by_cloud:
        backups_by_cloud[cloud_name] = []
    backups_by_cloud[cloud_name].append(backup_id)

    for id in [1, backup_id]:
        logger.info(f"Restoring backup-id: {id}")
        assert await restore_cluster(
            ops_test,
            id,  # backup_id of the 1st backup and then the latest backup
            unit_ip,
            leader_id,
        )
        assert await start_and_check_continuous_writes(ops_test, unit_ip, app)
