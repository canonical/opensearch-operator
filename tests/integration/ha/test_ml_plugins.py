#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import random
import json
import asyncio

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids_ips,
    get_leader_unit_ip,
)
from tests.integration.ha.helpers import (
    app_name,
)
from tests.integration.ha.helpers_data import (
    create_index,
    search,
    bulk_insert,
)

from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD


def generate_bulk_training_data(
    n: int, ndims: int, index_name: str, vector_name: str, has_result: bool = False
) -> str:
    random.seed("seed")
    print("The seed for randomness is: 'seed'")

    data = random.randombytes(n * ndims)
    if has_result:
        responses = random.randombytes(n)
    result = ""
    result_list = []
    for i in range(n):
        result += json.dumps({"index": {"_index": index_name, "_id": i}}) + "\n"
        result_list.append([float(data[j]) for j in range(i * ndims, (i + 1) * ndims)])
        inter = {vector_name: result_list[i]}
        if has_result:
            inter["price"] = float(responses[i])
        result += json.dumps(inter) + "\n"
    return result, result_list


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(
            my_charm, num_units=3, series=SERIES, config={"plugin_opensearch_knn": True}),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.abort_on_fail
async def test__search_with_hnsw_faiss(ops_test: OpsTest) -> None:
    """Uploads data and runs a query search against the FAISS KNNEngine."""
    import pdb; pdb.set_trace()

    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # create index with r_shards = nodes - 1
    index_name = "test_index"
    vector_name = "test-field"
    await create_index(
        ops_test,
        app,
        leader_unit_ip,
        index_name,
        r_shards=len(units) - 1,
        extra_index_settings={"knn": "true", "knn.algo_param.ef_search": 100},
        extra_mappings={
            "properties": {
                vector_name: {
                    "type": "knn_vector",
                    "dimension": 4,
                    "method": {
                        "name": "hnsw",
                        "space_type": "innerproduct",
                        "engine": "faiss",
                        "parameters": {"ef_construction": 256, "m": 48}
                    }
                }
            }
        }
    )
    payload, payload_list = generate_bulk_training_data(100, 8, index_name, vector_name, has_result=True)
    # Insert data in bulk
    await bulk_insert(ops_test, app, leader_unit_ip, payload)
    query = {
        "size": 2,
        "query": {
            "knn": {
                vector_name: {
                    "vector": payload_list[0],
                    "k": 2
                }
            }
        }
    }
    s = await search(ops_test, app, leader_unit_ip, index_name, query)
    print(s)
