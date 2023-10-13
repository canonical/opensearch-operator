#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import RetryError

from tests.integration.ha.helpers import app_name
from tests.integration.ha.helpers_data import bulk_insert, create_index, search
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    check_cluster_formation_successful,
    get_application_unit_ids_ips,
    get_application_unit_names,
    get_leader_unit_ip,
    http_request,
)
from tests.integration.plugins.helpers import (
    create_index_and_bulk_insert,
    generate_bulk_training_data,
    get_application_unit_ids_start_time,
    is_each_unit_restarted,
    is_knn_training_complete,
    mlcommons_load_model_to_node,
    mlcommons_model_predict,
    mlcommons_register_model,
    mlcommons_wait_task_model,
    run_knn_training,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

TRAINING_END_TO_END_DATA_INDEX = "test_end_to_end"


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
async def test_knn_search_with_hnsw_faiss(ops_test: OpsTest) -> None:
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
        index_name, vector_name, docs_count=100, dimensions=4, has_result=True
    )
    # Insert data in bulk
    await bulk_insert(ops_test, app, leader_unit_ip, payload)
    query = {"size": 2, "query": {"knn": {vector_name: {"vector": payload_list[0], "k": 2}}}}
    docs = await search(ops_test, app, leader_unit_ip, index_name, query)
    assert len(docs) == 2


@pytest.mark.abort_on_fail
async def test_knn_search_with_hnsw_nmslib(ops_test: OpsTest) -> None:
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
        index_name, vector_name, docs_count=100, dimensions=4, has_result=True
    )
    # Insert data in bulk
    await bulk_insert(ops_test, app, leader_unit_ip, payload)
    query = {"size": 2, "query": {"knn": {vector_name: {"vector": payload_list[0], "k": 2}}}}
    docs = await search(ops_test, app, leader_unit_ip, index_name, query)
    assert len(docs) == 2


@pytest.mark.abort_on_fail
async def test_knn_training_search(ops_test: OpsTest) -> None:
    """Tests the entire cycle of KNN plugin.

    1) Enters data and trains a model in "test_end_to_end"
    2) Trains model: "test_end_to_end_with_ivf_faiss_model"
    3) Once training is complete, creates a target index and connects with the model
    4) Disables KNN plugin: the search must fail
    5) Re-enables the plugin: search must succeed and return two vectors.
    """
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    # Get since when each unit has been active

    # create index with r_shards = nodes - 1
    index_name = TRAINING_END_TO_END_DATA_INDEX
    vector_name = "test_end_to_end_with_ivf_faiss_vector"
    model_name = "test_end_to_end_with_ivf_faiss_model"
    await create_index_and_bulk_insert(
        ops_test, app, leader_unit_ip, index_name, len(units) - 1, vector_name
    )
    await run_knn_training(
        ops_test,
        app,
        leader_unit_ip,
        model_name,
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
    # wait for training to finish -> fails with an exception otherwise
    assert await is_knn_training_complete(
        ops_test, app, leader_unit_ip, model_name
    ), "KNN training did not complete."

    # Creates the target index, to use the model
    payload_list = await create_index_and_bulk_insert(
        ops_test,
        app,
        leader_unit_ip,
        "test_end_to_end_with_ivf_faiss_target",
        len(units) - 1,
        vector_name="target-field",
        model_name=model_name,
    )

    # Set the config to false, then to true
    for knn_enabled in [False, True]:
        # get current timestamp, to compare with restarts later
        ts = await get_application_unit_ids_start_time(ops_test, APP_NAME)
        await ops_test.model.applications[APP_NAME].set_config(
            {"plugin_opensearch_knn": str(knn_enabled)}
        )
        await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", idle_period=15)
        # Now use it to compare with the restart
        assert await is_each_unit_restarted(ops_test, APP_NAME, ts)
        assert await check_cluster_formation_successful(
            ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=APP_NAME)
        ), "Restart happened but cluster did not start correctly"
        query = {
            "size": 2,
            "query": {"knn": {"target-field": {"vector": payload_list[0], "k": 2}}},
        }
        # If search eventually fails, then an exception is raised and the test fails as well
        try:
            docs = await search(
                ops_test,
                app,
                leader_unit_ip,
                "test_end_to_end_with_ivf_faiss_target",
                query,
                retries=3,
            )
            assert (
                knn_enabled and len(docs) == 2
            ), f"KNN enabled: {knn_enabled} and search results: {len(docs)}."
        except RetryError:
            # The search should fail if knn_enabled is false
            assert not knn_enabled


@pytest.mark.skip(reason="Given LLM size and current GH runners, jumping this test")
@pytest.mark.abort_on_fail
async def test_mlcommons_llm_model_register_and_prediction(ops_test: OpsTest) -> None:
    """Uploads and runs the model."""
    app = (await app_name(ops_test)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # Redefine sync-up job time
    await http_request(
        ops_test,
        "PUT",
        f"https://{leader_unit_ip}:9200/_cluster/settings",
        app=app,
        payload={"persistent": {"plugins.ml_commons.sync_up_job_interval_in_seconds": 600}},
    )

    task_id = await mlcommons_register_model(
        ops_test,
        app,
        leader_unit_ip,
        model_config={
            "name": "huggingface/sentence-transformers/all-MiniLM-L12-v2",
            "version": "1.0.1",
            "model_format": "TORCH_SCRIPT",
        },
    )

    model_id = await mlcommons_wait_task_model(ops_test, app, leader_unit_ip, task_id)
    assert model_id is not None, "The model_id is None when registering model"

    task_id = (await mlcommons_load_model_to_node(ops_test, app, leader_unit_ip, model_id)).get(
        "task_id", None
    )
    await mlcommons_wait_task_model(ops_test, app, leader_unit_ip, task_id)

    result = await mlcommons_model_predict(
        ops_test,
        app,
        leader_unit_ip,
        model_id,
        prediction_configs={
            "text_docs": ["This test worked?"],
            "return_number": True,
            "target_response": ["sentence_embedding"],
        },
    )
    shape_count = result["inference_results"][0]["output"][0]["shape"][0]
    assert shape_count > 0
    assert shape_count == len(result["inference_results"][0]["output"][0]["data"])


@pytest.mark.abort_on_fail
async def test_mlcommons_kmeans_model(ops_test: OpsTest) -> None:
    """Uploads and runs the model. This method reuses the data index used for FAISS IVF."""
    app = (await app_name(ops_test)) or APP_NAME

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # Redefine sync-up job time
    await http_request(
        ops_test,
        "PUT",
        f"https://{leader_unit_ip}:9200/_cluster/settings",
        app=app,
        payload={"persistent": {"plugins.ml_commons.sync_up_job_interval_in_seconds": 600}},
    )

    # train kmeans
    output = await http_request(
        ops_test,
        "POST",
        f"https://{leader_unit_ip}:9200/_plugins/_ml/_train/kmeans",
        app=app,
        payload={
            "parameters": {"centroids": 3, "iterations": 10, "distance_type": "COSINE"},
            "input_query": {"_source": ["price"], "size": 100},
            "input_index": [TRAINING_END_TO_END_DATA_INDEX],
        },
    )
    print(output)
    assert output["status"] == "COMPLETED", "Failed during kmeans training"
    model_id = output["model_id"]

    task_id = (await mlcommons_load_model_to_node(ops_test, app, leader_unit_ip, model_id)).get(
        "task_id", None
    )
    await mlcommons_wait_task_model(ops_test, app, leader_unit_ip, task_id)

    result = await mlcommons_model_predict(
        ops_test,
        app,
        leader_unit_ip,
        model_id,
        prediction_type="kmeans",
        prediction_configs={
            "input_query": {"_source": ["price"], "size": 1},
            "input_index": [TRAINING_END_TO_END_DATA_INDEX],
        },
    )
    assert result["status"] == "COMPLETED"
    assert len(result["prediction_result"]["rows"]) > 0
