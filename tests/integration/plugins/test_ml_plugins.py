#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.helpers import app_name
from tests.integration.ha.helpers_data import bulk_insert, create_index
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids_ips,
    get_leader_unit_ip,
)
from tests.integration.plugins.helpers import (
    create_index_and_bulk_insert,
    generate_bulk_training_data,
    run_knn_training,
    wait_all_units_restarted_or_fail,
    wait_for_knn_training,
    search,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy an OpenSearch cluster."""
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(
            my_charm, num_units=3, series=SERIES, config={"plugin_opensearch_knn": True}
        ),
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
async def test_search_with_hnsw_faiss(ops_test: OpsTest) -> None:
    """Uploads data and runs a query search against the FAISS KNNEngine."""
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # create index with r_shards = nodes - 1
    index_name = "test_search_with_hnsw_faiss"
    vector_name = "test_search_with_hnsw_faiss_vector"
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
                        "parameters": {"ef_construction": 256, "m": 48},
                    },
                }
            }
        },
    )
    payload, payload_list = generate_bulk_training_data(
        100, 4, index_name, vector_name, has_result=True
    )
    # Insert data in bulk
    await bulk_insert(ops_test, app, leader_unit_ip, payload)
    query = {"size": 2, "query": {"knn": {vector_name: {"vector": payload_list[0], "k": 2}}}}
    s = await search(ops_test, app, leader_unit_ip, index_name, query)
    assert len(s) == 2
    assert "query_shard_exception" not in json.dumps(s)


@pytest.mark.abort_on_fail
async def test_search_with_hnsw_nmslib(ops_test: OpsTest) -> None:
    """Uploads data and runs a query search against the NMSLIB KNNEngine."""
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # create index with r_shards = nodes - 1
    index_name = "test_search_with_hnsw_nmslib"
    vector_name = "test_search_with_hnsw_nmslib_vector"
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
                        "space_type": "l2",
                        "engine": "nmslib",
                        "parameters": {"ef_construction": 256, "m": 48},
                    },
                }
            }
        },
    )
    payload, payload_list = generate_bulk_training_data(
        100, 4, index_name, vector_name, has_result=True
    )
    # Insert data in bulk
    await bulk_insert(ops_test, app, leader_unit_ip, payload)
    query = {"size": 2, "query": {"knn": {vector_name: {"vector": payload_list[0], "k": 2}}}}
    s = await search(ops_test, app, leader_unit_ip, index_name, query)
    assert len(s) == 2
    assert "query_shard_exception" not in json.dumps(s)


@pytest.mark.abort_on_fail
async def test_train_search_with_ivf_faiss(ops_test: OpsTest) -> None:
    """Uploads data and runs a query search against the FAISS KNNEngine."""
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # create index with r_shards = nodes - 1
    index_name = "test_train_search_with_ivf_faiss_training"
    vector_name = "test_train_search_with_ivf_faiss_vector"
    model_name = "test_train_search_with_ivf_faiss_model"
    await create_index_and_bulk_insert(
        ops_test, app, leader_unit_ip, index_name, len(units) - 1, vector_name
    )

    # train the model
    await run_knn_training(
        ops_test,
        app,
        leader_unit_ip,
        "test_train_search_with_ivf_faiss_model",
        {
            "training_index": index_name,
            "training_field": vector_name,
            "dimension": 4,
            "method": {
                "name": "ivf",
                "engine": "faiss",
                "space_type": "l2",
                "parameters": {"nlist": 4, "nprobes": 2},
            },
        },
    )

    # wait for training to finish
    finished = False
    for i in range(10):
        if await wait_for_knn_training(ops_test, app, leader_unit_ip, model_name):
            finished = True
            break
        print("test_train_search_with_ivf_faiss - Waiting for training to finish...")
        await asyncio.sleep(15)

    assert finished


@pytest.mark.abort_on_fail
async def test_disable_re_enable_knn(ops_test: OpsTest) -> None:
    """Disables the KNN plugin, check restart happened, test unreachable and re-enable it."""
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    # Get since when each unit has been active
    active_since = {unit: None for unit in ops_test.model.applications[APP_NAME].units}
    active_since = await wait_all_units_restarted_or_fail(active_since)

    # create index with r_shards = nodes - 1
    index_name = "test_end_to_end_with_ivf_faiss_training"
    vector_name = "test_end_to_end_with_ivf_faiss_vector"
    model_name = "test_end_to_end_with_ivf_faiss_model"
    payload_list = await create_index_and_bulk_insert(
        ops_test, app, leader_unit_ip, index_name, len(units) - 1, vector_name
    )

    training_config = {
        "training_index": index_name,
        "training_field": vector_name,
        "dimension": 4,
        "method": {
            "name": "ivf",
            "engine": "faiss",
            "space_type": "l2",
            "parameters": {"nlist": 4, "nprobes": 2},
        },
    }
    await run_knn_training(ops_test, app, leader_unit_ip, model_name, training_config)
    # wait for training to finish
    finished = False
    for i in range(10):
        if await wait_for_knn_training(ops_test, app, leader_unit_ip, model_name):
            finished = True
            break
        print("test_disable_re_enable_knn - Waiting for training to finish...")
        await asyncio.sleep(15)
    assert finished

    # Set the config to false, then to true
    for conf in [False, True]:
        await ops_test.model.applications[APP_NAME].set_config({"plugin_opensearch_knn": str(conf)})
        await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", idle_period=15)
        active_since = await wait_all_units_restarted_or_fail(active_since)
        query_works = True
        try:
            query = {"size": 2, "query": {"knn": {vector_name: {"vector": payload_list[0], "k": 2}}}}
            s = await search(ops_test, app, leader_unit_ip, index_name, query)
        except Exception as e:
            print(f"test_disable_re_enable_knn: training fails with {e}")
            query_works = False
        assert query_works == conf # If config is false, then query should fail, and vice-versa
