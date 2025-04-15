#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..ha.helpers import app_name
from ..ha.helpers_data import bulk_insert, create_index
from ..ha.test_horizontal_scaling import IDLE_PERIOD
from ..helpers import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids_ips,
    get_leader_unit_ip,
    http_request,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .helpers import (
    generate_bulk_training_data,
    mlcommons_load_model_to_node,
    mlcommons_model_predict,
    mlcommons_register_model,
    mlcommons_wait_task_model,
)

logger = logging.getLogger(__name__)


TRAINING_END_TO_END_DATA_INDEX = "test_end_to_end"


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy_small_deployment(ops_test: OpsTest) -> None:
    """Build and deploy an OpenSearch cluster."""
    if await app_name(ops_test):
        return

    charm = await ops_test.build_charm(".")

    model_conf = MODEL_CONFIG.copy()
    # Make it more regular as COS relation-broken really happens on the
    # next hook call in each opensearch unit.
    # If this value is changed, then update the sleep accordingly at:
    #  test_prometheus_exporter_disabled_by_cos_relation_gone
    model_conf["update-status-hook-interval"] = "1m"
    await ops_test.model.set_config(model_conf)

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            charm,
            num_units=3,
            series=SERIES,
            config={"plugin_opensearch_knn": False} | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
    )

    await wait_until(
        ops_test,
        apps=[APP_NAME],
        units_statuses=["blocked"],
        wait_for_exact_units={APP_NAME: 3},
        timeout=3400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.group(1)
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


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_mlcommons_kmeans_model(ops_test: OpsTest) -> None:
    """Uploads and runs the model. This method reuses the data index used for FAISS IVF."""
    app = (await app_name(ops_test)) or APP_NAME

    units = await get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    await create_index(
        ops_test,
        app,
        leader_unit_ip,
        TRAINING_END_TO_END_DATA_INDEX,
        r_shards=len(units) - 1,
    )
    payload, _ = generate_bulk_training_data(
        TRAINING_END_TO_END_DATA_INDEX,
        docs_count=100,
        dimensions=4,
        has_result=True,
        vector_name=TRAINING_END_TO_END_DATA_INDEX + "_vector",
    )
    # Insert data in bulk
    await bulk_insert(ops_test, app, leader_unit_ip, payload)

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
