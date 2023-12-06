#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import base64
import json
import logging
import os

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import app_name, assert_continuous_writes_consistency
from tests.integration.ha.helpers_data import (
    create_index,
    default_doc,
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
    run_action,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


S3_INTEGRATOR_NAME = "s3-integrator"


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


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy an HA cluster of OpenSearch and corresponding S3 integration."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.

    if await app_name(ops_test):
        return

    if (
        "S3_BUCKET" not in os.environ
        or "S3_SERVER_URL" not in os.environ
        or "S3_REGION" not in os.environ
        or "S3_ACCESS_KEY" not in os.environ
        or "S3_SECRET_KEY" not in os.environ
    ):
        logger.exception("Missing S3 configs in os.environ.")
        raise Exception("Missing s3")

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    tls_config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    s3_config = {
        "bucket": os.environ["S3_BUCKET"],
        "path": "/",
        "endpoint": os.environ["S3_SERVER_URL"],
        "region": os.environ["S3_REGION"],
    }

    # Convert to integer as environ always returns string
    app_num_units = int(os.environ.get("TEST_NUM_APP_UNITS", None) or 3)

    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=tls_config),
        ops_test.model.deploy(S3_INTEGRATOR_NAME, channel="stable", config=s3_config),
        ops_test.model.deploy(my_charm, num_units=app_num_units, series=SERIES),
    )
    # Set the access/secret keys
    action = await run_action(
        ops_test,
        0,
        "sync-s3-credentials",
        params={
            "access-key": os.environ["S3_ACCESS_KEY"],
            "secret-key": os.environ["S3_SECRET_KEY"],
        },
        app=S3_INTEGRATOR_NAME,
    )
    logger.info(f"sync-s3-credentials output: {action}")

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
async def test_backup_cluster(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Runs the backup process whilst writing to the cluster into 'noisy-index'."""
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # create index with r_shards = nodes - 1
    test_backup_index = "test_backup_index"
    await create_index(ops_test, app, leader_unit_ip, test_backup_index, r_shards=len(units) - 1)

    # index document
    doc_id = 10
    await index_doc(ops_test, app, leader_unit_ip, test_backup_index, doc_id)

    # check that the doc can be retrieved from any node
    logger.info("Test backup index: searching")
    for u_id, u_ip in units.items():
        docs = await search(
            ops_test,
            app,
            u_ip,
            test_backup_index,
            query={"query": {"term": {"_id": doc_id}}},
            preference="_only_local",
        )
        # Validate the index and document are present
        assert len(docs) == 1
        assert docs[0]["_source"] == default_doc(test_backup_index, doc_id)

    leader_id = await get_leader_unit_id(ops_test, app)

    action = await run_action(ops_test, leader_id, "create-backup")
    logger.info(f"create-backup output: {action}")

    assert action.status == "completed"

    list_backups = await run_action(ops_test, leader_id, "list-backups")
    logger.info(f"list-backups output: {list_backups}")

    assert list_backups.status == "completed"
    assert len(json.loads(list_backups.response["snapshots"])) == int(action.response["backup-id"])

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
