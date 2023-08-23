#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import random

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.helpers import app_name
from tests.integration.ha.helpers_data import (
    bulk_insert,
    create_index,
    mlcommons_load_model_to_node,
    mlcommons_predict_model,
    mlcommons_upload_model,
    mlcommons_wait_task_model,
    search,
    set_knn_training,
    wait_for_knn_training,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids_ips,
    get_leader_unit_ip,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME


def generate_bulk_training_data(
    n: int, ndims: int, index_name: str, vector_name: str, has_result: bool = False
) -> str:
    random.seed("seed")
    print("The seed for randomness is: 'seed'")

    data = random.randbytes(n * ndims)
    if has_result:
        responses = random.randbytes(n)
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
            my_charm,
            num_units=3,
            series=SERIES,
            config={"plugin_opensearch_knn": True, "plugin_opensearch_mlcommons": True},
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

    async def _create_index_and_bulk_insert(
        ops_test, app, endpoint, index_name, shards, vector_name, model_name=None
    ):
        if model_name:
            extra_mappings = {
                "properties": {
                    vector_name: {
                        "type": "knn_vector",
                        "model_id": model_name,
                    }
                }
            }
            extra_settings = {"index.knn": "true"}
        else:
            extra_mappings = {
                "properties": {
                    vector_name: {
                        "type": "knn_vector",
                        "dimension": 4,
                    }
                }
            }
            extra_settings = {}

        await create_index(
            ops_test,
            app,
            endpoint,
            index_name,
            r_shards=shards,
            extra_index_settings=extra_settings,
            extra_mappings=extra_mappings,
        )
        payload, payload_list = generate_bulk_training_data(
            100, 4, index_name, vector_name, has_result=True
        )
        # Insert data in bulk
        await bulk_insert(ops_test, app, endpoint, payload)
        return payload_list

    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # create index with r_shards = nodes - 1
    index_name = "test_train_search_with_ivf_faiss_training"
    vector_name = "test_train_search_with_ivf_faiss_vector"
    model_name = "test_train_search_with_ivf_faiss_model"
    await _create_index_and_bulk_insert(
        ops_test, app, leader_unit_ip, index_name, len(units) - 1, vector_name
    )

    # train the model
    await set_knn_training(
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
        print("test_train_search_with_ivf_faiss - Waiting for training to finish.........")
        await asyncio.sleep(15)

    assert finished


@pytest.mark.abort_on_fail
async def test_mlcommons_upload_and_predict_model(ops_test: OpsTest) -> None:
    """Uploads and predicts a model."""

    async def __wait_model_task(task_id: str):
        for _ in range(5):
            model_id = await mlcommons_wait_task_model(ops_test, app, leader_unit_ip, task_id)
        assert model_id is not None
        return model_id

    app = (await app_name(ops_test)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    task_id = (
        await mlcommons_upload_model(
            ops_test,
            app,
            leader_unit_ip,
            model_config={
                "name": "huggingface/sentence-transformers/all-MiniLM-L12-v2",
                "version": "1.0.1",
                "model_format": "TORCH_SCRIPT",
            },
        )
    ).get("task_id", None)

    assert task_id is not None
    model_id = await __wait_model_task(task_id)

    task_id = (await mlcommons_load_model_to_node(ops_test, app, leader_unit_ip, model_id)).get(
        "task_id", None
    )

    assert task_id is not None
    model_id = await __wait_model_task(task_id)

    result = await mlcommons_predict_model(
        ops_test,
        app,
        leader_unit_ip,
        model_id,
        text_docs={
            "text_docs": ["This test worked?"],
            "return_number": True,
            "target_response": ["sentence_embedding"],
        },
    )
    shape_count = result["inference_results"][0]["output"][0]["shape"][0]
    assert shape_count == len(result["inference_results"][0]["output"][0]["data"])
