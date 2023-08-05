#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    app_name,
    assert_continuous_writes_consistency,
    update_restart_delay,
)
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
    get_application_unit_ids,
    get_application_unit_ids_ips,
    get_leader_unit_ip,
    run_action,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

S3_APP_NAME = "s3-integrator"

logger = logging.getLogger(__name__)


ORIGINAL_RESTART_DELAY = 20
RESTART_DELAY = 360


@pytest.fixture()
async def reset_restart_delay(ops_test: OpsTest):
    """Resets service file delay on all units."""
    yield
    app = (await app_name(ops_test)) or APP_NAME
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, ORIGINAL_RESTART_DELAY)


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


@pytest.fixture()
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    await c_writes.start(repl_on_all_nodes=True)
    yield
    await c_writes.clear()
    logger.info("\n\n\n\nThe writes have been cleared.\n\n\n\n")


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    # Deploy S3 operator.
    s3config = {
        "bucket": "s3://testbucket",
        "endpoint": "http://10.165.186.142",
    }
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
        ops_test.model.deploy(S3_APP_NAME, channel="stable", config=s3config),
    )

    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME],
        status="blocked",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    await run_action(
        ops_test,
        0,
        "sync-s3-credentials",
        params={"access-key": "fooAccessKey", "secret-key": "fooSecretKey"},
        app=S3_APP_NAME,
    )

    # Relate it to OpenSearch to set up TLS and S3
    await asyncio.gather(
        ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME),
        ops_test.model.relate(APP_NAME, S3_APP_NAME),
    )
    await ops_test.model.wait_for_idle(
        apps=[S3_APP_NAME, TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.abort_on_fail
async def test_backup_and_restore_under_load(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check consistency, ie write to node, read data from remaining nodes.

    1. Create index with replica shards equal to number of nodes - 1.
    2. Index data.
    3. Query data from all the nodes (all the nodes should contain a copy of the data).
    """
    import pdb

    pdb.set_trace()
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    leader_id = list(units.keys())[list(units.values()).index(leader_unit_ip)]

    # create index with r_shards = nodes - 1
    index_name = "test_index"
    await create_index(ops_test, app, leader_unit_ip, index_name, r_shards=len(units) - 1)

    # index document
    doc_id = 12
    await index_doc(ops_test, app, leader_unit_ip, index_name, doc_id)

    await run_action(ops_test, leader_id, "create-backup", app=APP_NAME)
    o = ""
    for i in range(0, 10):
        await asyncio.sleep(20)
        o = await run_action(ops_test, leader_id, "get-backup-status", app=APP_NAME)
        if "completed" in o:
            break
    assert "completed" in o

    backup_id = json.load(
        await run_action(ops_test, leader_id, "get-backup-status", app=APP_NAME)
    )[0]
    # Now recover
    await run_action(ops_test, leader_id, "restore", params={"backup-id": backup_id})

    # check that the doc can be retrieved from any node
    for u_id, u_ip in units.items():
        docs = await search(
            ops_test,
            app,
            u_ip,
            index_name,
            query={"query": {"term": {"_id": doc_id}}},
            preference="_only_local",
        )
        assert len(docs) == 1
        assert docs[0]["_source"] == default_doc(index_name, doc_id)

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
