#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

import pytest
from pytest_operator.plugin import OpsTest

from ..ha.helpers_data import bulk_insert, create_index, delete_index, index_doc
from ..helpers import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
    UNIT_IDS,
    get_leader_unit_ip,
    http_request,
)
from ..helpers_deployments import wait_until

logger = logging.getLogger(__name__)


DASHBOARDS_APP_NAME = "opensearch-dashboards"
SMTP_INTEGRATOR = "smtp-integrator"
TLS_CERTIFICATES_APP_NAME = "self-signed-certificates"
TLS_STABLE_CHANNEL = "latest/stable"

TEST_INDEX = "test-index"
TEST_DOCS = [
    {"passage_text": "Hello world", "id": "s1", "test_field": "us-west-2"},
    {"passage_text": "Hi planet", "id": "s2", "test_field": "us-east-1"},
]
INGEST_PIPELINE_ID = "test-ingest-pipeline"
TEXT_EMBEDDING_OUTPUT_DIM = 384
TEXT_EMBEDDING_MODEL = {
    "name": "huggingface/sentence-transformers/all-MiniLM-L6-v2",
    "version": "1.0.1",
    "model_format": "TORCH_SCRIPT",
}


def bulk_encode(docs: List[Dict[str, Any]], index_name: str) -> str:
    """Helper method to encode docs for bulk insert"""
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index_name}}))
        lines.append(json.dumps(doc))

    return "\n".join(lines) + "\n"


async def poll_until(
    ops_test: OpsTest,
    endpoint: str,
    condition: Callable,
    method: str = "GET",
    payload: Optional[dict] = None,
    timeout: int = 60,
    interval: int = 5,
) -> bool:
    """Poll endpoint until condition is true or timeout"""
    logger.info(f"Polling {endpoint}...")
    try:
        async with asyncio.timeout(timeout):
            while True:
                response = await http_request(ops_test, method, endpoint, payload)
                if condition(response):
                    logger.info("Done: condition met")
                    return True
                logger.info(f"Condition not met: {response}")
                await asyncio.sleep(interval)
    except asyncio.TimeoutError:
        logger.info("Polling timed out")
        raise


async def list_keystore_keys(ops_test: OpsTest, app: str, unit_id: int) -> str:
    """List keys in OpenSearch keystore on given unit"""
    logger.info(f"Running command on {app}/{unit_id}: sudo snap run opensearch.keystore list")
    return_code, stdout, _ = await ops_test.juju(
        "exec",
        "--model",
        ops_test.model.name,
        "--unit",
        f"{app}/{unit_id}",
        "--",
        "sudo",
        "snap",
        "run",
        "opensearch.keystore",
        "list",
    )

    return stdout.split("\n")


@pytest.mark.skip_if_deployed
async def test_build_and_deploy_active(ops_test: OpsTest, charm, series) -> None:
    """Build and deploy one unit of OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.deploy(
        charm,
        num_units=len(UNIT_IDS),
        series=series,
        config=CONFIG_OPTS,
    )
    await ops_test.model.deploy(
        DASHBOARDS_APP_NAME,
        channel="2/edge",
        series=series,
    )

    await ops_test.model.deploy(
        SMTP_INTEGRATOR,
        channel="latest/edge",
    )

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
    )
    await wait_until(ops_test, apps=[TLS_CERTIFICATES_APP_NAME], apps_statuses=["active"])

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(DASHBOARDS_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(DASHBOARDS_APP_NAME, APP_NAME)

    await wait_until(
        ops_test,
        apps=[APP_NAME, DASHBOARDS_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={APP_NAME: len(UNIT_IDS), DASHBOARDS_APP_NAME: 1},
    )
    assert len(ops_test.model.applications[APP_NAME].units) == len(UNIT_IDS)


async def test_smtp_credentials_written_to_keystore(ops_test: OpsTest) -> None:
    """Test that SMTP credentials are written to the OpenSearch keystore."""
    config = {"user": "smtp.user", "password": "supersecret", "host": "smtp.host"}
    await ops_test.model.applications[SMTP_INTEGRATOR].set_config(config)

    await ops_test.model.integrate(f"{SMTP_INTEGRATOR}:smtp", APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME, SMTP_INTEGRATOR],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={APP_NAME: len(UNIT_IDS), SMTP_INTEGRATOR: 1},
    )
    expected_keys = [
        "opensearch.notifications.core.email.smtp.user.password",
        "opensearch.notifications.core.email.smtp.user.username",
    ]

    # ensure keys are written on all units
    check_keys = [list_keystore_keys(ops_test, APP_NAME, unit_id) for unit_id in UNIT_IDS]
    results = await asyncio.gather(*check_keys)
    logger.info("Checking if expected keys written to all nodes")
    for keys in results:
        for expected_key in expected_keys:
            assert expected_key in keys, f"A unit is missing expected key {expected_key}"
    logger.info("All keys written")

    # remove stmp relation
    await ops_test.model.applications[APP_NAME].destroy_relation(
        f"{SMTP_INTEGRATOR}:smtp", APP_NAME
    )
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={APP_NAME: len(UNIT_IDS), SMTP_INTEGRATOR: 1},
    )

    check_keys = [list_keystore_keys(ops_test, APP_NAME, unit_id) for unit_id in UNIT_IDS]
    results = await asyncio.gather(*check_keys)
    logger.info("Checking if keys removed from all nodes")
    for keys in results:
        for expected_key in expected_keys:
            assert expected_key not in keys, f"A unit still has key {expected_key}"
    logger.info("All keys removed.")

    # remove smtp integrator
    await ops_test.model.remove_application(SMTP_INTEGRATOR)


async def test_reports_scheduler(ops_test: OpsTest) -> None:
    """Test that the reports scheduler plugin is enabled and functional."""
    dash_leader_unit_ip = await get_leader_unit_ip(ops_test, app=DASHBOARDS_APP_NAME)
    dash_base_url = f"https://{dash_leader_unit_ip}:5601"

    # download sample data
    sample_data = "ecommerce"
    logger.info(f"Downloading sample {sample_data} data...")
    response = await http_request(
        ops_test,
        "POST",
        f"{dash_base_url}/api/sample_data/{sample_data}",
        extra_headers={"osd-xsrf": "true"},
    )
    logger.info(f"Download response: {response}")
    assert response["opensearchIndicesCreated"], f"Sample data '{sample_data}' not downloaded"

    logger.info("Finding a dashboard..")
    response = await http_request(
        ops_test,
        "GET",
        f"{dash_base_url}/api/saved_objects/_find?type=search&search_fields=title&search={sample_data}",
    )
    logger.info(f"Search fields response: {response}")
    dash_id = response["saved_objects"][0]["id"]

    end_ms = int(time.time() * 1000)
    begin_ms = end_ms - 15 * 60 * 1000
    payload = {
        "beginTimeMs": begin_ms,
        "endTimeMs": end_ms,
        "reportDefinitionDetails": {
            "id": "csv-reports",
            "createdTimeMs": end_ms,
            "lastUpdatedTimeMs": end_ms,
            "reportDefinition": {
                "name": "csv-report-name",
                "description": "CSV from saved search",
                "isEnabled": True,
                "source": {
                    "type": "SavedSearch",
                    "id": dash_id,
                    "origin": f"https://{dash_leader_unit_ip}:5601",
                    "description": "ecommerce saved search",
                },
                "format": {"fileFormat": "Csv", "duration": "PT15M"},
                "trigger": {"triggerType": "Download"},
                "delivery": {
                    "configIds": [],
                    "title": "",
                    "textDescription": "",
                    "htmlDescription": "",
                },
            },
        },
        "status": "Success",
    }

    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_plugins/_reports/on_demand"
    logger.info("Creating report...")
    response = await http_request(ops_test, "PUT", endpoint, payload)
    logger.info(f"Report response: {response}")
    assert response["reportInstance"].get("id"), "No report instance created"


async def test_sql_plugin(ops_test: OpsTest) -> None:
    """Test that the SQL plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    # create index
    await create_index(ops_test, APP_NAME, leader_unit_ip, TEST_INDEX)

    # insert test docs
    await bulk_insert(ops_test, APP_NAME, leader_unit_ip, bulk_encode(TEST_DOCS, TEST_INDEX))
    await http_request(ops_test, "POST", f"{base_url}/{TEST_INDEX}/_refresh")

    # select target doc
    target = TEST_DOCS[-1]
    target_id = target["id"]
    target_text = target["passage_text"]

    # create query
    query = {"query": f"SELECT id, passage_text FROM {TEST_INDEX} WHERE id = '{target_id}'"}
    endpoint = f"https://{leader_unit_ip}:9200/_plugins/_sql"
    response = await http_request(ops_test, "POST", endpoint, query)
    logger.info(f"\nSQL query response: {response}")
    assert response["size"] == 1, "Unexpected SQL result"
    assert response["datarows"][0][-1] == target_text, "Unexpected SQL result"


async def test_ism_and_job_scheduler_plugins(ops_test: OpsTest) -> None:
    """Test that the ISM and job scheduler plugins are enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    # set job interval to 1m (min value)
    settings = {
        "persistent": {
            "plugins.index_state_management.job_interval": 1,
            "plugins.index_state_management.jitter": 0,
        }
    }

    await http_request(
        ops_test,
        "PUT",
        f"{base_url}/_cluster/settings",
        settings,
    )

    # create index with alias
    index_alias = "ism-test"
    initial_index = f"{index_alias}-000001"
    expected_end_index = (
        f"{index_alias}-000002"  # after rollover the new index will have the number incremented
    )
    await create_index(
        ops_test,
        APP_NAME,
        leader_unit_ip,
        initial_index,
        extra_index_settings={"plugins.index_state_management.rollover_alias": index_alias},
    )

    # set alias
    await http_request(
        ops_test,
        "PUT",
        f"{base_url}/{initial_index}/_alias/{index_alias}",
        {"is_write_index": True},
    )

    # create policy to rollover index after min doc count (1)
    policy_id = "rollover"
    rollover = {
        "policy": {
            "description": "rollover",
            "default_state": "hot",
            "states": [
                {"name": "hot", "actions": [{"rollover": {"min_doc_count": 1}}], "transitions": []}
            ],
        }
    }
    await http_request(ops_test, "PUT", f"{base_url}/_plugins/_ism/policies/{policy_id}", rollover)

    # attach policy
    await http_request(
        ops_test, "POST", f"{base_url}/_plugins/_ism/add/{initial_index}", {"policy_id": policy_id}
    )

    # add doc to trigger rollover
    await index_doc(ops_test, APP_NAME, leader_unit_ip, index_alias, 1)

    # wait for job interval time (1m) to pass for job scheduler to run policy checks
    logger.info("Waiting for job interval to pass before polling for index rollover...")
    await asyncio.sleep(60)

    # poll if new index created (should trigger within 1m but can take longer)
    assert await poll_until(
        ops_test,
        f"{base_url}/_alias/{index_alias}",
        lambda aliases: expected_end_index in aliases,
        timeout=60 * 3,
    ), "Index did not rollover before timeout"

    # delete indices
    await delete_index(ops_test, APP_NAME, leader_unit_ip, initial_index)
    await delete_index(ops_test, APP_NAME, leader_unit_ip, expected_end_index)
    await http_request(ops_test, "DELETE", f"{base_url}/_plugins/_ism/policies/{policy_id}")


async def test_anomaly_detection(ops_test: OpsTest) -> None:
    """Test that the anomaly plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    detectors_url = f"{base_url}/_plugins/_anomaly_detection/detectors"

    anomaly_index = "anomaly-index"
    await create_index(
        ops_test,
        APP_NAME,
        leader_unit_ip,
        anomaly_index,
        extra_mappings={
            "properties": {"timestamp": {"type": "date"}, "value": {"type": "double"}}
        },
    )
    # insert time series data with an anomaly
    start = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    n = 500
    docs = []
    for i in range(n):
        timestamp = (start + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")
        value = 1000.0 if i == 200 else 10.0 + (i % 5)
        docs.append({"timestamp": timestamp, "value": value})

    await bulk_insert(ops_test, APP_NAME, leader_unit_ip, bulk_encode(docs, anomaly_index))
    await http_request(ops_test, "POST", f"{base_url}/{anomaly_index}/_refresh")

    # create detector
    detector = {
        "name": "anonmaly-detection",
        "time_field": "timestamp",
        "indices": [anomaly_index],
        "feature_attributes": [
            {
                "feature_name": "sum_value",
                "feature_enabled": True,
                "aggregation_query": {"sum_value": {"sum": {"field": "value"}}},
            }
        ],
        "detection_interval": {"period": {"interval": 1, "unit": "Minutes"}},
    }

    # preview detector
    start_time = int(start.timestamp() * 1000)
    end_time = int((start + timedelta(minutes=n)).timestamp() * 1000)
    payload = {
        "detector": detector,
        "period_start": start_time,
        "period_end": end_time,
    }
    response = await http_request(
        ops_test,
        "POST",
        f"{detectors_url}/_preview",
        payload,
    )
    assert len(response.get("anomaly_result")) > 0, "No anomalies found"
    await delete_index(ops_test, APP_NAME, leader_unit_ip, anomaly_index)


async def test_async_search_plugin(ops_test: OpsTest) -> None:
    """Test that the async search plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_plugins/_asynchronous_search"

    # create async search
    payload = {
        "query": {"match_all": {}},
        "size": 1,
    }
    response = await http_request(
        ops_test,
        "POST",
        f"{endpoint}?index={TEST_INDEX}&wait_for_completion_timeout=0s&keep_on_completion=true",
        payload,
    )
    logger.info(f"Async Search response: {response}")
    async_job_id = response["id"]

    # poll until complete
    assert await poll_until(
        ops_test,
        f"{endpoint}/{async_job_id}",
        lambda progress: progress["state"] == "STORE_RESIDENT",
    ), "Async search did not complete before timeou"


async def test_alerting_plugin(ops_test: OpsTest) -> None:
    """Test that the alerting plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_plugins/_alerting/monitors"

    # create monitor
    payload = {
        "name": "alerting-test",
        "monitor-type": "query_level_monitor",
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [
            {"search": {"indices": [TEST_INDEX], "query": {"size": 0, "query": {"match_all": {}}}}}
        ],
        "triggers": [
            {
                "name": "has_docs",
                "severity": "1",
                "condition": {"script": {"source": "ctx.results[0].hits.total.value > 0"}},
                "actions": [],
            }
        ],
    }

    response = await http_request(ops_test, "POST", endpoint, payload)
    monitor_id = response["_id"]

    logger.info(f"Executing monitor {monitor_id} dryrun")
    response = await http_request(
        ops_test,
        "POST",
        f"{endpoint}/{monitor_id}/_execute?dryrun=true",
    )

    assert response["trigger_results"], "No alerting trigger results"


async def test_query_insights_plugin(ops_test: OpsTest) -> None:
    """Test that the query insights plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    response = await http_request(ops_test, "GET", f"{base_url}/_insights/top_queries")
    assert response["top_queries"], "No top queries returned"


async def test_notifications_plugin(ops_test: OpsTest) -> None:
    """Test that the notifications plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    notifications_endpoint = f"{base_url}/_plugins/_notifications"

    response = await http_request(ops_test, "GET", f"{notifications_endpoint}/features")
    assert response["allowed_config_type_list"]

    # create channel
    payload = {
        "config": {
            "name": "test-webhook",
            "config_type": "webhook",
            "is_enabled": True,
            "webhook": {"url": "http://127.0.0.1:9200"},  # connection will be refused
        }
    }
    logger.info("Creating notification channel")
    response = await http_request(ops_test, "POST", f"{notifications_endpoint}/configs", payload)
    channel_id = response["config_id"]
    logger.info(f"Created: {channel_id}")

    # attempt to send test notification
    logger.info(f"Attempting test notification to channel {channel_id} (should attempt but fail)")
    response = await http_request(
        ops_test, "GET", f"{notifications_endpoint}/feature/test/{channel_id}"
    )

    logger.info(f"Notifications test response: {response}")
    assert (
        "Failed to send webhook" in response["error"]["reason"]
    ), "Did not attempt to send webhook notification"


async def test_ml_plugin(ops_test: OpsTest) -> None:
    """Test that the ML plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    # train and predict
    payload = {
        "parameters": {"centroids": 2, "iterations": 1, "distance_type": "EUCLIDEAN"},
        "input_data": {
            "column_metas": [
                {"name": "k1", "column_type": "DOUBLE"},
                {"name": "k2", "column_type": "DOUBLE"},
            ],
            "rows": [
                {
                    "values": [
                        {"column_type": "DOUBLE", "value": 1.0},
                        {"column_type": "DOUBLE", "value": 2.0},
                    ]
                },
                {
                    "values": [
                        {"column_type": "DOUBLE", "value": 1.0},
                        {"column_type": "DOUBLE", "value": 4.0},
                    ]
                },
                {
                    "values": [
                        {"column_type": "DOUBLE", "value": 1.0},
                        {"column_type": "DOUBLE", "value": 0.0},
                    ]
                },
                {
                    "values": [
                        {"column_type": "DOUBLE", "value": 10.0},
                        {"column_type": "DOUBLE", "value": 2.0},
                    ]
                },
                {
                    "values": [
                        {"column_type": "DOUBLE", "value": 10.0},
                        {"column_type": "DOUBLE", "value": 4.0},
                    ]
                },
                {
                    "values": [
                        {"column_type": "DOUBLE", "value": 10.0},
                        {"column_type": "DOUBLE", "value": 0.0},
                    ]
                },
            ],
        },
    }

    response = await http_request(
        ops_test, "POST", f"{base_url}/_plugins/_ml/_train_predict/kmeans", payload
    )
    assert response["status"] == "COMPLETED", "ML run did not complete"


async def test_observability_plugin(ops_test: OpsTest) -> None:
    """Test that the observability plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    # send PPL query
    payload = {"query": f"source = {TEST_INDEX}"}
    response = await http_request(ops_test, "POST", f"{base_url}/_plugins/_ppl", payload)
    assert response["size"] == len(TEST_DOCS)


async def test_flow_framework_plugin(ops_test: OpsTest) -> None:
    """Test that the flow framework plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_plugins/_flow_framework/workflow"

    # delete TEST_INDEX (the workflow will recreate it)
    await delete_index(ops_test, APP_NAME, leader_unit_ip, TEST_INDEX)

    # register model group
    ml_endpoint = f"{base_url}/_plugins/_ml"
    payload = {"name": "test_group", "description": "Test model group"}
    response = await http_request(
        ops_test, "POST", f"{ml_endpoint}/model_groups/_register", payload
    )
    model_group_id = response["model_group_id"]

    # register model
    payload = TEXT_EMBEDDING_MODEL | {"model_group_id": model_group_id}
    response = await http_request(ops_test, "POST", f"{ml_endpoint}/models/_register", payload)
    task_id = response["task_id"]

    # poll until registered
    assert await poll_until(
        ops_test, f"{ml_endpoint}/tasks/{task_id}", lambda status: status["state"] == "COMPLETED"
    ), "ML model registration did not complete before timeout"

    # get model id
    response = await http_request(ops_test, "GET", f"{ml_endpoint}/tasks/{task_id}")
    model_id = response["model_id"]

    # create semantic search workflow
    payload = {
        "create_ingest_pipeline.pipeline_id": INGEST_PIPELINE_ID,
        "create_ingest_pipeline.model_id": model_id,
        "create_index.name": TEST_INDEX,
        "text_embedding.field_map.output.dimension": TEXT_EMBEDDING_OUTPUT_DIM,
    }
    response = await http_request(
        ops_test, "POST", f"{endpoint}?use_case=semantic_search&provision=true", payload
    )
    workflow_id = response["workflow_id"]
    assert await poll_until(
        ops_test,
        f"{endpoint}/{workflow_id}/_status",
        lambda workflow: workflow["state"] == "COMPLETED",
    )

    # check if index was created
    resp_code = await http_request(
        ops_test, "GET", f"{base_url}/{TEST_INDEX}", resp_status_code=True
    )
    assert resp_code == 200, "Flow framework did not create index"


async def test_neural_search_plugin(ops_test: OpsTest) -> None:
    """Test that the neural search plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    # get model id used for ingesting documents to this index
    # ingest pipeline with id {INGEST_PIPELINE_ID} was created during flow framework test
    response = await http_request(
        ops_test, "GET", f"{base_url}/_ingest/pipeline/{INGEST_PIPELINE_ID}"
    )
    model_id = response[INGEST_PIPELINE_ID]["processors"][0]["text_embedding"]["model_id"]

    # deploy model
    response = await http_request(
        ops_test, "POST", f"{base_url}/_plugins/_ml/models/{model_id}/_deploy"
    )
    task_id = response["task_id"]

    # poll until model deployment complete
    assert await poll_until(
        ops_test,
        f"{base_url}/_plugins/_ml/tasks/{task_id}",
        lambda status: status["state"] == "COMPLETED",
    )

    # insert docs
    await bulk_insert(ops_test, APP_NAME, leader_unit_ip, bulk_encode(TEST_DOCS, TEST_INDEX))
    await http_request(ops_test, "POST", f"{base_url}/{TEST_INDEX}/_refresh")

    # run neural search
    k = 1
    payload = {
        "query": {
            "neural": {"passage_embedding": {"query_text": "planet", "model_id": model_id, "k": k}}
        }
    }
    response = await http_request(ops_test, "GET", f"{base_url}/{TEST_INDEX}/_search", payload)
    assert len(response["hits"]["hits"]) == k


async def test_ltr_plugin(ops_test: OpsTest) -> None:
    """Test that the learning-to-rank plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_ltr/_featureset"

    # initialize default feature store
    response = await http_request(ops_test, "PUT", f"{base_url}/_ltr")
    assert response["acknowledged"], "LTR index not created"

    # create feature set
    featureset = "test-featureset"
    feature = "test-feature"
    payload = {
        "featureset": {
            "features": [
                {
                    "name": feature,
                    "params": ["q"],
                    "template_language": "mustache",
                    "template": {"match": {"passage_text": "{{q}}"}},
                }
            ]
        }
    }
    response = await http_request(ops_test, "POST", f"{endpoint}/{featureset}", payload)
    assert response["result"] == "created", "Feature set not created"

    # create model using the featureset to score
    model = "test-lm"
    payload = {
        "model": {
            "name": model,
            "model": {"type": "model/linear", "definition": {feature: 1.0}},
        }
    }
    response = await http_request(
        ops_test, "POST", f"{base_url}/_ltr/_featureset/{featureset}/_createmodel", payload
    )
    assert response["result"] == "created", "LTR model not created"

    # learn ranking with model
    payload = {
        "query": {"match_all": {}},
        "rescore": [
            {
                "window_size": 10,
                "query": {"rescore_query": {"sltr": {"model": model, "params": {"q": "planet"}}}},
            }
        ],
        "size": 1,
    }
    response = await http_request(ops_test, "POST", f"{base_url}/{TEST_INDEX}/_search", payload)
    assert len(response["hits"]["hits"]) == 1
    await delete_index(ops_test, APP_NAME, leader_unit_ip, TEST_INDEX)


async def test_security_analytics_plugin(ops_test: OpsTest) -> None:
    """Test that the security analytics plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_plugins/_security_analytics"

    # add custom rule to select doc with activity = dangerous
    sigma_rule = """
title: Critical Detector
id: 11111111-2222-3333-4444-555555555555
description: Detect docs where region == west
status: experimental
author: superadmin
date: 2025/08/27
logsource:
  product: linux
detection:
  select:
    activity: "suspicious"
  condition: select
level: low"""
    response = await http_request(
        ops_test, "POST", f"{endpoint}/rules?category=linux", payload=sigma_rule
    )
    rule_id = response["_id"]
    assert rule_id, "Rule not created"

    log_index = "log-index"
    await create_index(
        ops_test,
        APP_NAME,
        leader_unit_ip,
        log_index,
        extra_mappings={
            "properties": {
                "activity": {"type": "keyword"},
                "user": {"type": "keyword"},
            }
        },
    )
    # create index
    # await http_request(
    #     ops_test,
    #     "POST",
    #     f"{endpoint}/mappings",
    #     {
    #         "index_name": log_index,
    #         "rule_topic": "linux",
    #         "partial": True,
    #         "alias_mappings": {"properties": {"": {"type": "alias", "path": "EventID"}}},
    #     },
    # )

    # create detector
    payload = {
        "enabled": True,
        "name": "danger-detector",
        "detector_type": "linux",
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [
            {
                "detector_input": {
                    "indices": [log_index],
                    "custom_rules": [{"id": rule_id}],
                }
            }
        ],
    }
    response = await http_request(ops_test, "POST", f"{endpoint}/detectors", payload)
    logger.info(f"\nDetectors response: {response}")
    detector_id = response["_id"]
    assert detector_id, "Security Analytics detector not created"

    docs = [
        {"name": "a", "activity": "not suspicious"},
        {"name": "b", "activity": "very normal"},
        {"name": "c", "activity": "suspicious"},
    ]
    await bulk_insert(ops_test, APP_NAME, leader_unit_ip, bulk_encode(docs, log_index))
    await http_request(ops_test, "POST", f"{base_url}/{log_index}/_refresh")

    logger.info("Waiting for detector schedule period to pass...")
    await asyncio.sleep(60)

    # check for findings
    assert await poll_until(
        ops_test,
        f"{endpoint}/findings/_search?detector_id={detector_id}",
        lambda findings: findings.get("total_findings") == 1,
        timeout=60 * 3,
    )
    await http_request(ops_test, "DELETE", f"{endpoint}/detectors/{detector_id}")
    await http_request(ops_test, "DELETE", f"{endpoint}/rules/{rule_id}?category=linux")
    await delete_index(ops_test, APP_NAME, leader_unit_ip, log_index)


async def test_custom_codecs_plugin(ops_test: OpsTest) -> None:
    """Test that the custom codecs plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    # create index with zstd codec
    zstd = "zstd-index"
    default = "default-index"
    await create_index(
        ops_test, APP_NAME, leader_unit_ip, zstd, extra_index_settings={"codec": "zstd"}
    )
    await create_index(ops_test, APP_NAME, leader_unit_ip, default)

    # insert same docs to indices with different codecs
    docs = [{"x": i, "blob": "A" * 100} for i in range(5000)]
    body = bulk_encode(docs, zstd) + "\n" + bulk_encode(docs, default)
    await bulk_insert(ops_test, APP_NAME, leader_unit_ip, body)
    # await index_doc(ops_test, APP_NAME, leader_unit_ip, codecs, 1, doc={"x": 1})

    response = await http_request(
        ops_test, "GET", f"{base_url}/{zstd}/_settings?flat_settings=true"
    )
    codec = response[zstd]["settings"]["index.codec"]
    assert codec == "zstd", f"Expected codec 'zstd' but found {codec}"

    # compare size of indices, zstd index should be smaller
    stats = await http_request(ops_test, "GET", f"{base_url}/{zstd},{default}/_stats/store")
    zstd_size = stats["indices"][zstd]["total"]["store"]["size_in_bytes"]
    default_size = stats["indices"][default]["total"]["store"]["size_in_bytes"]

    logger.info(f"Index sizes - zstd: {zstd_size} default: {default_size}")
    assert zstd_size < default_size
    await delete_index(ops_test, APP_NAME, leader_unit_ip, zstd)
    await delete_index(ops_test, APP_NAME, leader_unit_ip, default)


async def test_geospatial_plugin(ops_test: OpsTest) -> None:
    """Test that the geospatial plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_plugins/geospatial/ip2geo/datasource"

    # create data source
    datasource = "cities"
    manifest_url = "https://geoip.maps.opensearch.org/v1/geolite2-city/manifest.json"
    payload = {
        "endpoint": manifest_url,
        "update_interval_in_days": 3,
    }
    success = await http_request(ops_test, "PUT", f"{endpoint}/{datasource}", payload)
    assert success, "Could not download Geospatial data source manifest"

    # wait for data source to download
    logger.info("Waiting for data source to be available")
    assert await poll_until(
        ops_test,
        f"{endpoint}/{datasource}",
        lambda ds: ds["datasources"][0]["state"] == "AVAILABLE",
        timeout=60 * 5,
        interval=10,
    ), "Geo data source not available before timeout"

    geo_pipeline = "geo-pipeline"
    payload = {"processors": [{"ip2geo": {"field": "ip", "datasource": datasource}}]}
    await http_request(ops_test, "PUT", f"{base_url}/_ingest/pipeline/{geo_pipeline}", payload)

    # get geo-enriched data
    payload = {"docs": [{"_index": "testindex1", "_id": "1", "_source": {"ip": "172.0.0.1"}}]}
    response = await http_request(
        ops_test, "POST", f"{base_url}/_ingest/pipeline/{geo_pipeline}/_simulate", payload
    )
    logger.info(f"Geospatial response: {response}")
    assert response["docs"][0]["doc"]["_source"]["ip2geo"], "Unexpected geo processor used"


async def test_skills_plugin(ops_test: OpsTest) -> None:
    """Test that the skills plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_plugins/_ml/agents"

    # register flow agent to run CatIndexTool
    payload = {
        "name": "skills_test",
        "type": "flow",
        "tools": [{"type": "CatIndexTool", "name": "list"}],
    }
    response = await http_request(ops_test, "POST", f"{endpoint}/_register", payload)
    agent_id = response["agent_id"]

    # run the agent
    payload = {"parameters": {"question": "How many indices do I have?"}}

    response = await http_request(ops_test, "POST", f"{endpoint}/{agent_id}/_execute", payload)
    assert len(response["inference_results"]) > 0, "Flow agent did not return any results"
