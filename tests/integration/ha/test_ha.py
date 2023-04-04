#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import app_name, assert_continuous_writes_consistency
from tests.integration.ha.helpers_data import (
    create_index,
    default_doc,
    delete_index,
    index_doc,
    search,
)
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids_ips,
    get_leader_unit_ip,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


SECOND_APP_NAME = "second-opensearch"


@pytest.fixture()
def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    return ContinuousWrites(ops_test)


@pytest.fixture()
async def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield
    await c_writes.clear()


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
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="edge", config=config),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME], status="active", timeout=1000
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.abort_on_fail
async def test_replication_across_members(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check consistency, ie write to node, read data from remaining nodes.

    1. Create index with replica shards equal to number of nodes - 1.
    2. Index data.
    3. Query data from all the nodes (all the nodes should contain a copy of the data).
    """
    app = (await app_name(ops_test)) or APP_NAME

    units = get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # create index with r_shards = nodes - 1
    index_name = "test_index"
    await create_index(ops_test, leader_unit_ip, index_name, r_shards=len(units) - 1)

    # index document
    doc_id = 12
    await index_doc(ops_test, leader_unit_ip, index_name, doc_id)

    # check that the doc can be retrieved from any node
    for u_id, u_ip in units.items():
        docs = await search(
            ops_test,
            u_ip,
            index_name,
            query={"query": {"term": {"_id": doc_id}}},
            preference="_only_local",
        )
        assert len(docs) == 1
        assert docs[0]["_source"] == default_doc(index_name, doc_id)

    await delete_index(ops_test, leader_unit_ip, index_name)

    # continuous writes checks
    await assert_continuous_writes_consistency(c_writes)


async def test_multi_clusters_db_isolation(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check that writes in cluster not replicated to another cluster."""
    app = (await app_name(ops_test)) or APP_NAME

    index_name = "test_index_unique_cluster_dbs"

    # index document in the current cluster
    main_app_leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    await index_doc(ops_test, main_app_leader_unit_ip, index_name, doc_id=1)

    # deploy new cluster
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(my_charm, num_units=1, application_name=SECOND_APP_NAME)
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(apps=[SECOND_APP_NAME], status="active")

    # index document in second cluster
    second_app_leader_ip = await get_leader_unit_ip(ops_test, app=SECOND_APP_NAME)
    await index_doc(ops_test, main_app_leader_unit_ip, index_name, doc_id=2, app=SECOND_APP_NAME)

    # fetch all documents in each cluster
    current_app_docs = await search(ops_test, main_app_leader_unit_ip, index_name)
    second_app_docs = await search(ops_test, second_app_leader_ip, index_name, app=SECOND_APP_NAME)

    # check that the only doc indexed in each cluster is different
    assert len(current_app_docs) == 1
    assert len(second_app_docs) == 1
    assert current_app_docs[0] != second_app_docs[0]

    # cleanup
    await delete_index(ops_test, main_app_leader_unit_ip, index_name)
    await ops_test.model.remove_application(
        SECOND_APP_NAME, block_until_done=True, force=True, destroy_storage=True
    )

    # continuous writes checks
    await assert_continuous_writes_consistency(c_writes)
