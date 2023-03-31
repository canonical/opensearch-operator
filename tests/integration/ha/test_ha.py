#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    app_name,
    assert_continuous_writes_consistency,
    get_elected_cm_unit_id,
    get_shards_by_index,
)
from tests.integration.ha.helpers_data import (
    default_doc,
    delete_index,
    get_doc,
    index_doc,
)
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids_ips,
    get_leader_unit_ip,
    http_request,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)

IDLE_PERIOD = 120


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

    1. check data can be indexed from a node and be searched from any other node.
    2. index data and only query the node where the replica shard resides.
    """
    units = get_application_unit_ids_ips(ops_test)
    leader_unit_ip = await get_leader_unit_ip(ops_test)

    # 1. index document using the elected cm ip
    cm_id = await get_elected_cm_unit_id(ops_test, leader_unit_ip)
    cm_ip = units[cm_id]

    index_name = "test_index"
    doc_id = 12
    await index_doc(ops_test, cm_ip, index_name, doc_id)

    # check that the doc can be retrieved from any node
    for u_id, u_ip in units.items():
        doc = await get_doc(ops_test, u_ip, index_name, doc_id)
        assert doc["_source"] == default_doc(index_name, doc_id)

    await delete_index(ops_test, leader_unit_ip, index_name)

    # 2. index data and exclusively query node hosting the replica shard
    doc_id = 13
    await index_doc(ops_test, cm_ip, index_name, doc_id)
    shards = await get_shards_by_index(ops_test, leader_unit_ip, index_name)
    replica_shard = [shard for shard in shards if not shard.is_prim][0]

    unit_with_replica_shard_ip = units[replica_shard.unit_id]

    # query exclusively the node with the replica shard
    docs = (
        await http_request(
            ops_test,
            "GET",
            (
                f"https://{unit_with_replica_shard_ip}:9200/{index_name}/_search"
                f"?preference=_only_nodes:{replica_shard.node_id}"
            ),
        )
    )["hits"]["hits"]

    assert len(docs) == 1
    assert docs[0]["_source"] == default_doc(index_name, doc_id)

    await delete_index(ops_test, leader_unit_ip, index_name)

    # continuous writes checks
    await assert_continuous_writes_consistency(c_writes)
