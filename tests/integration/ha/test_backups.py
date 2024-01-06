#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import os

# from pathlib import Path
#
# import boto3
import pytest
from pytest_operator.plugin import OpsTest

from ..ha.helpers import assert_continuous_writes_consistency
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
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .continuous_writes import ContinuousWrites
from .helpers_data import create_index, default_doc, index_doc, search
from .test_horizontal_scaling import IDLE_PERIOD

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
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:  # , cloud_credentials) -> None:
    """Build and deploy an HA cluster of OpenSearch and corresponding S3 integration."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.

    if await app_name(ops_test):
        return

    s3_storage = None
    if (
        "S3_BUCKET" in os.environ
        and "S3_SERVER_URL" in os.environ
        and "S3_REGION" in os.environ
        and "S3_ACCESS_KEY" in os.environ
        and "S3_SECRET_KEY" in os.environ
    ):
        s3_config = {
            "bucket": os.environ["S3_BUCKET"],
            "path": "/",
            "endpoint": os.environ["S3_SERVER_URL"],
            "region": os.environ["S3_REGION"],
        }
        s3_storage = "ceph"
    elif "AWS_ACCESS_KEY" in os.environ and "AWS_SECRET_KEY" in os.environ:
        s3_config = CLOUD_CONFIGS["aws"].copy()
        s3_storage = "aws"
    elif "GCP_ACCESS_KEY" in os.environ and "GCP_SECRET_KEY" in os.environ:
        s3_config = CLOUD_CONFIGS["gcp"].copy()
        s3_storage = "gcp"
    else:
        logger.exception("Missing S3 configs in os.environ.")
        raise Exception("Missing s3")

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    tls_config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}

    # Convert to integer as environ always returns string
    app_num_units = int(os.environ.get("TEST_NUM_APP_UNITS", None) or 3)

    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=tls_config),
        ops_test.model.deploy(S3_INTEGRATOR_NAME, channel="stable", config=s3_config),
        ops_test.model.deploy(my_charm, num_units=app_num_units, series=SERIES),
    )
    # Set the access/secret keys
    if s3_storage == "ceph":
        s3_creds = {
            "access-key": os.environ["S3_ACCESS_KEY"],
            "secret-key": os.environ["S3_SECRET_KEY"],
        }
    #    else:
    #        s3_creds = cloud_credentials[s3_storage].copy()

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


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_backup_cluster(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
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

    action = await run_action(ops_test, leader_id, "create-backup")
    logger.info(f"create-backup output: {action}")

    assert action.status == "completed"

    list_backups = await run_action(ops_test, leader_id, "list-backups", params={"output": "json"})
    logger.info(f"list-backups output: {list_backups}")

    # Expected format:
    # namespace(status='completed', response={'return-code': 0, 'backups': '{"1": ...}'})
    backups = json.loads(list_backups.response["backups"])
    assert list_backups.status == "completed"
    assert len(backups.keys()) == int(action.response["backup-id"])
    assert backups[action.response["backup-id"]]["state"] == "SUCCESS"

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_restore_cluster(
    ops_test: OpsTest,
) -> None:
    """Deletes the TEST_BACKUP_INDEX, restores the cluster and tries to search for index."""
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_id = await get_leader_unit_id(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    await http_request(
        ops_test,
        "DELETE",
        f"https://{leader_unit_ip}:9200/{TEST_BACKUP_INDEX}",
        app=app,
    )

    action = await run_action(ops_test, leader_id, "restore", params={"backup-id": 1})
    logger.info(f"restore output: {action}")
    assert action.status == "completed"

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
async def test_restore_cluster_after_app_destroyed(ops_test: OpsTest) -> None:
    """Deletes the entire OpenSearch cluster and redeploys from scratch.

    Restores the backup and then checks if the same TEST_BACKUP_INDEX is there.
    """
    app = (await app_name(ops_test)) or APP_NAME
    await ops_test.model.remove_application(app, block_until_done=True)
    app_num_units = int(os.environ.get("TEST_NUM_APP_UNITS", None) or 3)
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

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_id = await get_leader_unit_id(ops_test, app)

    action = await run_action(ops_test, leader_id, "restore", params={"backup-id": 1})
    logger.info(f"restore output: {action}")
    assert action.status == "completed"

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
async def test_remove_and_readd_s3_relation(ops_test: OpsTest) -> None:
    """Removes and re-adds the s3-credentials relation to test backup and restore."""
    app = (await app_name(ops_test)) or APP_NAME
    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_id = await get_leader_unit_id(ops_test, app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

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

    leader_id = await get_leader_unit_id(ops_test, app)

    action = await run_action(ops_test, leader_id, "create-backup")
    logger.info(f"create-backup output: {action}")

    assert action.status == "completed"

    list_backups = await run_action(ops_test, leader_id, "list-backups", params={"output": "json"})
    logger.info(f"list-backups output: {list_backups}")

    # Expected format:
    # namespace(status='completed', response={'return-code': 0, 'backups': '{"1": ...}'})
    backups = json.loads(list_backups.response["backups"])
    assert list_backups.status == "completed"
    assert len(backups.keys()) == int(action.response["backup-id"])
    assert backups[action.response["backup-id"]]["state"] == "SUCCESS"

    await http_request(
        ops_test,
        "DELETE",
        f"https://{leader_unit_ip}:9200/{TEST_BACKUP_INDEX}",
        app=app,
    )

    action = await run_action(
        ops_test, leader_id, "restore", params={"backup-id": int(action.response["backup-id"])}
    )
    logger.info(f"restore-backup output: {action}")
    assert action.status == "completed"

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
