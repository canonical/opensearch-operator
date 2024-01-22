#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import os
import random
import time

# from pathlib import Path
#
# import boto3
import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_attempt, wait_fixed

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import app_name, assert_continuous_writes_consistency
from tests.integration.ha.helpers_data import (
    create_index,
    default_doc,
    index_count,
    index_doc,
    search,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids_ips,
    get_leader_unit_id,
    get_leader_unit_ip,
    get_reachable_unit_ips,
    http_request,
    run_action,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


S3_INTEGRATOR_NAME = "s3-integrator"
TEST_BACKUP_DOC_ID = 10
CLOUD_CONFIGS = {
    "aws": {
        "endpoint": "https://s3.amazonaws.com",
        "bucket": "data-charms-testing",
        "path": "opensearch",
        "region": "us-east-1",
    },
    "gcp": {
        "endpoint": "https://storage.googleapis.com",
        "bucket": "data-charms-testing",
        "path": "opensearch",
        "region": "",
    },
}

backups_by_cloud = {}
value_before_backup, value_after_backup = None, None


# @pytest.fixture(scope="session")
# def cloud_credentials(github_secrets) -> dict[str, dict[str, str]]:
#     """Read cloud credentials."""
#     return {
#         "aws": {
#             "access-key": github_secrets["AWS_ACCESS_KEY"],
#             "secret-key": github_secrets["AWS_SECRET_KEY"],
#         },
#         "gcp": {
#             "access-key": github_secrets["GCP_ACCESS_KEY"],
#             "secret-key": github_secrets["GCP_SECRET_KEY"],
#         },
#     }


# @pytest.fixture(scope="session", autouse=True)
# def clean_backups_from_buckets(cloud_credentials) -> None:
#     """Teardown to clean up created backups from clouds."""
#     yield
#
#     logger.info("Cleaning backups from cloud buckets")
#     for cloud_name, config in CLOUD_CONFIGS.items():
#         backup = backups_by_cloud.get(cloud_name)
#
#         if not backup:
#             continue
#
#         session = boto3.session.Session(
#             aws_access_key_id=cloud_credentials[cloud_name]["access-key"],
#             aws_secret_access_key=cloud_credentials[cloud_name]["secret-key"],
#             region_name=config["region"],
#         )
#         s3 = session.resource("s3", endpoint_url=config["endpoint"])
#         bucket = s3.Bucket(config["bucket"])
#
#         # GCS doesn't support batch delete operation, so delete the objects one by one
#         backup_path = str(Path(config["path"]) / backups_by_cloud[cloud_name])
#         for bucket_object in bucket.objects.filter(Prefix=backup_path):
#             bucket_object.delete()


TEST_BACKUP_INDEX = "test_backup_index"


@pytest.fixture()
async def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    app = (await app_name(ops_test)) or APP_NAME
    return ContinuousWrites(ops_test, app)


@pytest.fixture()
async def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield

    reachable_ip = random.choice(await get_reachable_unit_ips(ops_test))
    await http_request(ops_test, "GET", f"https://{reachable_ip}:9200/_cat/nodes", json_resp=False)
    await http_request(
        ops_test, "GET", f"https://{reachable_ip}:9200/_cat/shards", json_resp=False
    )

    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


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


async def _wait_backup_finish(ops_test, leader_id):
    """Waits the backup to finish and move to the finished state or throws a RetryException."""
    for attempt in Retrying(stop=stop_after_attempt(8), wait=wait_fixed(15)):
        with attempt:
            action = await run_action(
                ops_test, leader_id, "list-backups", params={"output": "json"}
            )
            logger.debug(f"list-backups output: {action}")
            # Expected format:
            # namespace(status='completed', response={'return-code': 0, 'backups': '{"1": ...}'})
            backups = json.loads(action.response["backups"])
            logger.debug(f"Backups recovered: {backups}")
            assert action.status == "completed"  # The actual action status
            assert len(backups) > 0  # The number of backups
            for backup in backups.values():
                logger.debug(f"Backup is: {backup}")
                assert backup["state"] == "SUCCESS"  # The backup status


async def _assert_test_cont_writes_works(ops_test: OpsTest) -> ContinuousWrites:
    """Asserts that TEST_BACKUP_INDEX is writable while under continuous writes.

    Given we are restoring an index, we need to make sure ContinuousWrites restart at
    the tip of that index instead of doc_id = 0.

    Closes the writer at the end.
    """
    app = (await app_name(ops_test)) or APP_NAME
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    initial_count = await index_count(ops_test, app, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    logger.info(
        f"Index {ContinuousWrites.INDEX_NAME} has {initial_count} documents, starting there"
    )
    writer = ContinuousWrites(ops_test, app, initial_count=initial_count)
    await writer.start()

    try:
        total_writes = await writer.count()

        units = await get_application_unit_ids_ips(ops_test, app=app)
        app = (await app_name(ops_test)) or APP_NAME
        doc_id = TEST_BACKUP_DOC_ID  # This is the next doc id, after the previous test

        # check that the doc can be retrieved from any node
        logger.info("Test backup index: searching")
        for u_ip in units.values():
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

        assert await writer.count() > total_writes
    except Exception as e:
        await writer.stop()
        raise e

    time.sleep(5)
    result = await writer.stop()
    assert result.count > initial_count


async def _backup_cluster(ops_test: OpsTest) -> None:
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    await create_index(ops_test, app, leader_unit_ip, TEST_BACKUP_INDEX, r_shards=len(units) - 1)

    # index document
    doc_id = TEST_BACKUP_DOC_ID
    await index_doc(ops_test, app, leader_unit_ip, TEST_BACKUP_INDEX, doc_id)

    # check that the doc can be retrieved from any node
    logger.info("Test backup index: searching")
    for u_ip in units.values():
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

    action = await run_action(ops_test, leader_id, "create-backup")
    logger.debug(f"create-backup output: {action}")

    assert action.status == "completed"
    await _wait_backup_finish(ops_test, leader_id)


async def _restore_cluster(ops_test: OpsTest) -> None:
    app = (await app_name(ops_test)) or APP_NAME
    leader_id = await get_leader_unit_id(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # For testing:
    # delete the TEST_BACKUP_INDEX
    await http_request(
        ops_test,
        "DELETE",
        f"https://{leader_unit_ip}:9200/{TEST_BACKUP_INDEX}",
        app=app,
    )

    action = await run_action(ops_test, leader_id, "restore", params={"backup-id": 1})
    logger.debug(f"restore output: {action}")
    assert action.status == "completed"


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    ops_test: OpsTest, microceph
) -> None:  # , cloud_credentials) -> None:
    """Build and deploy an HA cluster of OpenSearch and corresponding S3 integration."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.

    if await app_name(ops_test):
        return

    s3_config = {
        "bucket": "data-charms-testing",
        "path": "/",
        "endpoint": microceph["url"],
        "region": "default",
    }

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    tls_config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}

    # Convert to integer as environ always returns string
    app_num_units = 3

    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=tls_config),
        ops_test.model.deploy(S3_INTEGRATOR_NAME, channel="stable", config=s3_config),
        ops_test.model.deploy(my_charm, num_units=app_num_units, series=SERIES),
    )
    s3_creds = {
        "access-key": microceph["access-key"],
        "secret-key": microceph["secret-key"],
    }

    await run_action(
        ops_test,
        0,
        "sync-s3-credentials",
        params=s3_creds,
        app=S3_INTEGRATOR_NAME,
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.relate(APP_NAME, S3_INTEGRATOR_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )


@pytest.mark.abort_on_fail
async def test_01_backup_cluster(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Runs the backup process whilst writing to the cluster into 'noisy-index'."""
    await _backup_cluster(ops_test)

    app = (await app_name(ops_test)) or APP_NAME
    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.abort_on_fail
async def test_02_restore_cluster(ops_test: OpsTest) -> None:
    """Deletes the TEST_BACKUP_INDEX, restores the cluster and tries to search for index."""
    app = (await app_name(ops_test)) or APP_NAME
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    await _restore_cluster(ops_test)
    # Count the number of docs in the index
    count = await index_count(ops_test, app, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    assert count > 0
    await _assert_test_cont_writes_works(ops_test)


@pytest.mark.abort_on_fail
async def test_03_restore_cluster_after_app_destroyed(
    ops_test: OpsTest,
) -> None:
    """Deletes the entire OpenSearch cluster and redeploys from scratch.

    Restores the backup and then checks if the same TEST_BACKUP_INDEX is there.
    """
    app = (await app_name(ops_test)) or APP_NAME
    await ops_test.model.remove_application(app, block_until_done=True)
    app_num_units = 3
    my_charm = await ops_test.build_charm(".")
    # Redeploy
    await asyncio.gather(
        ops_test.model.deploy(my_charm, num_units=app_num_units, series=SERIES),
    )
    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.relate(APP_NAME, S3_INTEGRATOR_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    app = (await app_name(ops_test)) or APP_NAME
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    # # We delete the series index from c_writes
    # # The idea is to ensure we will have data after restore
    # await http_request(
    #     ops_test,
    #     "DELETE",
    #     f"https://{leader_unit_ip}:9200/{ContinuousWrites.INDEX_NAME}",
    #     app=app,
    # )
    await _restore_cluster(ops_test)
    # Count the number of docs in the index
    count = await index_count(ops_test, app, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    assert count > 0

    await _assert_test_cont_writes_works(ops_test)


@pytest.mark.abort_on_fail
async def test_04_remove_and_readd_s3_relation(ops_test: OpsTest) -> None:
    """Removes and re-adds the s3-credentials relation to test backup and restore."""
    logger.info("Remove s3-credentials relation")
    # Remove relation
    await ops_test.model.applications[APP_NAME].destroy_relation(
        "s3-credentials", f"{S3_INTEGRATOR_NAME}:s3-credentials"
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    logger.info("Re-add s3-credentials relation")
    await ops_test.model.relate(APP_NAME, S3_INTEGRATOR_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    # Backup should generate a new backup id
    await _backup_cluster(ops_test)
    app = (await app_name(ops_test)) or APP_NAME
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    # # We delete the series index from c_writes
    # # The idea is to ensure we will have data after restore
    # await http_request(
    #     ops_test,
    #     "DELETE",
    #     f"https://{leader_unit_ip}:9200/{ContinuousWrites.INDEX_NAME}",
    #     app=app,
    # )
    await _restore_cluster(ops_test)
    # Count the number of docs in the index
    count = await index_count(ops_test, app, leader_unit_ip, ContinuousWrites.INDEX_NAME)
    assert count > 0
    await _assert_test_cont_writes_works(ops_test)
