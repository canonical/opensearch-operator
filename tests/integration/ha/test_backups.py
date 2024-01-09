#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import os
import uuid
from pathlib import Path

import boto3
import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_attempt, wait_fixed

from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    app_name,
    get_application_unit_ids_ips,
    get_leader_unit_id,
    get_leader_unit_ip,
    http_request,
    run_action,
)
from ..tls.helpers import TLS_CERTIFICATES_APP_NAME
from .helpers_data import create_index, default_doc, index_doc, search
from .test_horizontal_scaling import IDLE_PERIOD

logger = logging.getLogger(__name__)


backups_by_cloud = {}
value_before_backup, value_after_backup = None, None


@pytest.fixture(scope="session")
def microceph():
    """Starts microceph radosgw."""
    import subprocess

    if "microceph" not in subprocess.check_output(["sudo", "snap", "list"]).decode():
        import os

        import requests

        uceph = "/tmp/microceph.sh"

        with open(uceph, "w") as f:
            resp = requests.get(
                "https://raw.githubusercontent.com/canonical/microceph-action/main/microceph.sh"
            )
            f.write(resp.content.decode())

        os.chmod(uceph, 0o755)
        subprocess.check_output(
            [
                "sudo",
                uceph,
                "-c",
                "latest/edge",
                "-d",
                "/dev/sdi",
                "-a",
                "accesskey",
                "-s",
                "secretkey",
                "-b",
                "data-charms-testing",
                "-z",
                "5G",
            ]
        )
    # Now, return the configuration
    ip = subprocess.check_output(["hostname", "-I"]).decode().split()[0]
    return {"url": f"http://{ip}", "access-key": "accesskey", "secret-key": "secretkey"}


@pytest.fixture(scope="session")
def cloud_configs(github_secrets, microceph):
    # Add UUID to path to avoid conflict with tests running in parallel (e.g. multiple Juju
    # versions on a PR, multiple PRs)
    path = f"opensearch/{uuid.uuid4()}"

    results = {
        "microceph": {
            "endpoint": microceph["url"],
            "bucket": "data-charms-testing",
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
    if "GCP_ACCESS_KEY" in github_secrets:
        results["gcp"] = {
            "endpoint": "https://storage.googleapis.com",
            "bucket": "data-charms-testing",
            "path": path,
            "region": "",
        }
    return results


@pytest.fixture(scope="session")
def cloud_credentials(github_secrets, microceph) -> dict[str, dict[str, str]]:
    """Read cloud credentials."""
    results = {
        "microceph": {
            "access-key": microceph["access-key"],
            "secret-key": microceph["secret-key"],
        },
    }
    if "AWS_ACCESS_KEY" in github_secrets:
        results["aws"] = {
            "access-key": github_secrets["AWS_ACCESS_KEY"],
            "secret-key": github_secrets["AWS_SECRET_KEY"],
        }
    if "GCP_ACCESS_KEY" in github_secrets:
        results["gcp"] = {
            "access-key": github_secrets["GCP_ACCESS_KEY"],
            "secret-key": github_secrets["GCP_SECRET_KEY"],
        }
    return results


@pytest.fixture(scope="session", autouse=True)
def clean_backups_from_buckets(cloud_configs, cloud_credentials) -> None:
    """Teardown to clean up created backups from clouds."""
    yield

    logger.info("Cleaning backups from cloud buckets")
    for cloud_name, config in cloud_configs.items():
        backup = backups_by_cloud.get(cloud_name)

        if not backup:
            continue

        session = boto3.session.Session(
            aws_access_key_id=cloud_credentials[cloud_name]["access-key"],
            aws_secret_access_key=cloud_credentials[cloud_name]["secret-key"],
            region_name=config["region"],
        )
        s3 = session.resource("s3", endpoint_url=config["endpoint"])
        bucket = s3.Bucket(config["bucket"])

        # GCS doesn't support batch delete operation, so delete the objects one by one
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


async def _wait_backup_finish(ops_test, leader_id):
    """Waits the backup to finish and move to the finished state or throws a RetryException."""
    for attempt in Retrying(stop=stop_after_attempt(8), wait=wait_fixed(15)):
        with attempt:
            action = await run_action(
                ops_test, leader_id, "list-backups", params={"output": "json"}
            )
            logger.info(f"list-backups output: {action}")
            # Expected format:
            # namespace(status='completed', response={'return-code': 0, 'backups': '{"1": ...}'})
            backups = json.loads(action.response["backups"])
            logger.info(backups)
            assert action.status == "completed"  # The actual action status
            assert len(backups) > 0  # The number of backups
            for _, backup in backups.items():
                logger.info(f"Backup is: {backup}")
                assert backup["state"] == "SUCCESS"  # The backup status


TEST_BACKUP_INDEX = "test_backup_index"
S3_INTEGRATOR = "s3-integrator"
S3_INTEGRATOR_CHANNEL = "latest/edge"
TIMEOUT = 10 * 60
TEST_BACKUP_DOC_ID = 10


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    ops_test: OpsTest, self_signed_operator
) -> None:  # , cloud_credentials) -> None:
    """Build and deploy an HA cluster of OpenSearch and corresponding S3 integration."""
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Convert to integer as environ always returns string
    app_num_units = int(os.environ.get("TEST_NUM_APP_UNITS", None) or 2)
    await asyncio.gather(
        ops_test.model.deploy(S3_INTEGRATOR, channel=S3_INTEGRATOR_CHANNEL),
        ops_test.model.deploy(my_charm, num_units=app_num_units, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    tls = await self_signed_operator
    await ops_test.model.relate(APP_NAME, tls)
    await ops_test.model.relate(APP_NAME, S3_INTEGRATOR)
    await ops_test.model.wait_for_idle(
        apps=[tls, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_backup(ops_test: OpsTest, cloud_configs, cloud_credentials) -> None:
    """Runs the backup process whilst writing to the cluster into 'noisy-index'."""
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    await create_index(ops_test, app, leader_unit_ip, TEST_BACKUP_INDEX, r_shards=len(units) - 1)

    # index document
    doc_id = TEST_BACKUP_DOC_ID
    await index_doc(ops_test, app, leader_unit_ip, TEST_BACKUP_INDEX, doc_id)

    # check that the doc can be retrieved from any node
    logger.info("Test backup index: searching")
    for u_id, u_ip in units.items():
        docs = await search(
            ops_test,
            app,
            u_ip,
            TEST_BACKUP_INDEX,
            query={"query": {"term": {"_id": doc_id}}},
            preference="_only_local",
        )
        # Validate the index and document are present
        assert len(docs) == 1
        assert docs[0]["_source"] == default_doc(TEST_BACKUP_INDEX, doc_id)

    leader_id = await get_leader_unit_id(ops_test, app)

    for cloud_name, config in cloud_configs.items():
        # set the s3 config and credentials
        logger.info(f"Syncing credentials for {cloud_name}")
        await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

        # create backup
        logger.info("Creating backup")
        action = await run_action(ops_test, leader_id, "create-backup")
        logger.info(f"create-backup output: {action}")
        assert action.status == "completed"
        backup_id = int(action.response["backup-id"])

        await _wait_backup_finish(ops_test, leader_id)

        if cloud_name not in backups_by_cloud:
            backups_by_cloud[cloud_name] = []
        backups_by_cloud[cloud_name].append(backup_id)

        # check that the doc can be retrieved from any node
        logger.info("Test backup index: searching")
        for u_id, u_ip in units.items():
            docs = await search(
                ops_test,
                app,
                u_ip,
                TEST_BACKUP_INDEX,
                query={"query": {"term": {"_id": doc_id}}},
                preference="_only_local",
            )
            # Validate the index and document are present
            assert len(docs) == 1
            assert docs[0]["_source"] == default_doc(TEST_BACKUP_INDEX, doc_id)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_restore(ops_test: OpsTest, cloud_configs, cloud_credentials) -> None:
    """Deletes the TEST_BACKUP_INDEX, restores the cluster and tries to search for index."""
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_id = await get_leader_unit_id(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    for cloud_name, config in cloud_configs.items():
        assert len(backups_by_cloud[cloud_name]) > 0

        await http_request(
            ops_test,
            "DELETE",
            f"https://{leader_unit_ip}:9200/{TEST_BACKUP_INDEX}",
            app=app,
        )

        # set the s3 credentials and config
        logger.info(f"Syncing credentials for {cloud_name}")
        await _configure_s3(ops_test, config, cloud_credentials[cloud_name], app)

        # restore the latest backup
        id = backups_by_cloud[cloud_name][-1]
        logger.info(f"Restoring backup with id {id}")
        action = await run_action(ops_test, leader_id, "restore", params={"backup-id": id})
        assert action.status == "completed"
        logger.info(f"restore output: {action}")

        for attempt in Retrying(stop=stop_after_attempt(8), wait=wait_fixed(15)):
            with attempt:
                await asyncio.sleep(20)
                action = await run_action(ops_test, leader_id, "check-restore-status")
                logger.info(f"check-restore-status output: {action}")
                assert action.status == "completed"
                assert action.response["state"] == "successful restore!"
                break

        # ensure the correct inserted values exist
        logger.info(
            "Ensuring that the pre-backup inserted value exists in database,"
            " while post-backup inserted value does not"
        )
        # index document
        doc_id = TEST_BACKUP_DOC_ID
        # check that the doc can be retrieved from any node
        logger.info("Test backup index: searching")
        for u_id, u_ip in units.items():
            docs = await search(
                ops_test,
                app,
                u_ip,
                TEST_BACKUP_INDEX,
                query={"query": {"term": {"_id": doc_id}}},
                preference="_only_local",
            )
            # Validate the index and document are present
            assert len(docs) == 1
            assert docs[0]["_source"] == default_doc(TEST_BACKUP_INDEX, doc_id)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_restore_cluster_after_app_destroyed(
    ops_test: OpsTest, cloud_configs, cloud_credentials
) -> None:
    """Deletes the entire OpenSearch cluster and redeploys from scratch.

    Restores the backup and then checks if the same TEST_BACKUP_INDEX is there.
    """
    app = (await app_name(ops_test)) or APP_NAME
    await ops_test.model.remove_application(app, block_until_done=True)
    app_num_units = int(os.environ.get("TEST_NUM_APP_UNITS", None) or 2)
    my_charm = await ops_test.build_charm(".")
    # Redeploy
    await asyncio.gather(
        ops_test.model.deploy(my_charm, num_units=app_num_units, series=SERIES),
    )
    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.relate(APP_NAME, S3_INTEGRATOR)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    # This is the same check as the previous restore action.
    # Call the method again
    await test_restore(ops_test, cloud_configs, cloud_credentials)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_remove_and_readd_s3_relation(
    ops_test: OpsTest, cloud_configs, cloud_credentials
) -> None:
    """Removes and re-adds the s3-credentials relation to test backup and restore."""
    logger.info("Remove s3-credentials relation")
    # Remove relation
    await ops_test.model.applications[APP_NAME].destroy_relation(
        "s3-credentials", f"{S3_INTEGRATOR}:s3-credentials"
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    logger.info("Re-add s3-credentials relation")
    await ops_test.model.relate(APP_NAME, S3_INTEGRATOR)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    # Backup should generate a new backup id
    await test_backup(ops_test, cloud_configs, cloud_credentials)
    # There were only 2x backups per cloud
    # Ensure the counts of backup ids are correct and the values are different
    for cloud_name, config in cloud_configs.items():
        assert len(backups_by_cloud[cloud_name]) == 2
        assert backups_by_cloud[cloud_name][0] != backups_by_cloud[cloud_name][1]
    # This is the same check as the previous restore action.
    # Call the method again
    await test_restore(ops_test, cloud_configs, cloud_credentials)
