#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

import pytest
from pytest_operator.plugin import OpsTest

from ..ha.helpers import app_name
from ..ha.helpers_data import bulk_insert, create_index, delete_index, index_doc, search
from ..ha.test_horizontal_scaling import IDLE_PERIOD
from ..helpers import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
    get_application_unit_ids_ips,
    get_leader_unit_id,
    get_leader_unit_ip,
    get_secret_by_label,
    http_request,
    run_action,
    set_watermark,
)
from ..helpers_deployments import wait_until
from ..plugins.helpers import (
    bulk_encode,
    create_index_and_bulk_insert,
    generate_bulk_training_data,
    is_knn_training_complete,
    poll_until,
    run_knn_training,
)
from ..profiles.test_profiles import get_constraints
from ..relations.helpers import get_unit_relation_data
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


COS_APP_NAME = "grafana-agent"
COS_CHANNEL = "1/stable"
COS_RELATION_NAME = "cos-agent"
DASHBOARDS_APP_NAME = "opensearch-dashboards"
MAIN_ORCHESTRATOR_NAME = "main"
FAILOVER_ORCHESTRATOR_NAME = "failover"


ALL_GROUPS = {
    deploy_type: pytest.param(
        deploy_type,
        id=deploy_type,
        marks=[
            pytest.mark.group(id=deploy_type),
        ],
    )
    for deploy_type in ["large_deployment", "small_deployment"]
}

ALL_DEPLOYMENTS = list(ALL_GROUPS.values())
SMALL_DEPLOYMENTS = [ALL_GROUPS["small_deployment"]]
LARGE_DEPLOYMENTS = [ALL_GROUPS["large_deployment"]]

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


async def _wait_for_units(
    ops_test: OpsTest,
    deployment_type: str,
    wait_for_cos: bool = False,
) -> None:
    """Wait for all units to be active.

    This wait will behavior accordingly to small/large.
    """
    if deployment_type == "small_deployment":
        await wait_until(
            ops_test,
            apps=[APP_NAME],
            apps_statuses=["active"],
            units_statuses=["active"],
            timeout=1800,
            wait_for_exact_units={APP_NAME: 3},
            idle_period=IDLE_PERIOD,
        )
        if wait_for_cos:
            await wait_until(
                ops_test,
                apps=[COS_APP_NAME],
                units_statuses=["blocked"],
                timeout=1800,
                idle_period=IDLE_PERIOD,
            )
        return
    await wait_until(
        ops_test,
        apps=[
            TLS_CERTIFICATES_APP_NAME,
            MAIN_ORCHESTRATOR_NAME,
            FAILOVER_ORCHESTRATOR_NAME,
            APP_NAME,
        ],
        wait_for_exact_units={
            TLS_CERTIFICATES_APP_NAME: 1,
            MAIN_ORCHESTRATOR_NAME: 1,
            FAILOVER_ORCHESTRATOR_NAME: 2,
            APP_NAME: 1,
        },
        apps_statuses=["active"],
        units_statuses=["active"],
        timeout=1800,
        idle_period=IDLE_PERIOD,
    )
    if wait_for_cos:
        await wait_until(
            ops_test,
            apps=[COS_APP_NAME],
            units_statuses=["blocked"],
            timeout=1800,
            idle_period=IDLE_PERIOD,
        )


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy_small_deployment(
    ops_test: OpsTest, charm, series, deploy_type: str
) -> None:
    """Build and deploy an OpenSearch cluster."""
    if await app_name(ops_test):
        return

    model_conf = MODEL_CONFIG.copy()
    # Make it more regular as COS relation-broken really happens on the
    # next hook call in each opensearch unit.
    # If this value is changed, then update the sleep accordingly at:
    #  test_prometheus_exporter_disabled_by_cos_relation_gone
    model_conf["update-status-hook-interval"] = "1m"
    await ops_test.model.set_config(model_conf)
    constraints = await get_constraints(ops_test)

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            charm,
            num_units=3,
            series=series,
            constraints=constraints,
            config={"profile": "production"},
        ),
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)

    await _wait_for_units(ops_test, deploy_type)
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_prometheus_exporter_enabled_by_default(ops_test, deploy_type: str):
    """Test that Prometheus Exporter is running before the relation is there.

    Test only on small deployments scenario, as this is a more functional check to the plugin.
    """
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=APP_NAME)
    endpoint = f"https://{leader_unit_ip}:9200/_prometheus/metrics"
    response = await http_request(ops_test, "get", endpoint, app=APP_NAME, json_resp=False)

    response_str = response.content.decode("utf-8")
    assert response_str.count("opensearch_") > 500
    assert len(response_str.split("\n")) > 500


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_small_deployments_prometheus_exporter_cos_relation(
    ops_test, series, deploy_type: str
):
    await ops_test.model.deploy(COS_APP_NAME, channel=COS_CHANNEL, series=series)
    await ops_test.model.integrate(APP_NAME, COS_APP_NAME)
    await _wait_for_units(ops_test, deploy_type, wait_for_cos=True)

    # Check that the correct settings were successfully communicated to grafana-agent
    cos_leader_id = await get_leader_unit_id(ops_test, COS_APP_NAME)
    cos_leader_name = f"{COS_APP_NAME}/{cos_leader_id}"
    leader_id = await get_leader_unit_id(ops_test, APP_NAME)
    leader_name = f"{APP_NAME}/{leader_id}"
    relation_data = await get_unit_relation_data(
        ops_test, cos_leader_name, leader_name, COS_RELATION_NAME, "config"
    )
    if not isinstance(relation_data, dict):
        relation_data = json.loads(relation_data)
    relation_data = relation_data["metrics_scrape_jobs"][0]
    secret = await get_secret_by_label(ops_test, "opensearch:app:monitor-password")

    assert relation_data["basic_auth"]["username"] == "monitor"
    assert relation_data["basic_auth"]["password"] == secret["monitor-password"]

    admin_secret = await get_secret_by_label(ops_test, "opensearch:app:app-admin")
    assert relation_data["tls_config"]["ca"] == admin_secret["ca-cert"]
    assert relation_data["scheme"] == "https"


@pytest.mark.parametrize("deploy_type", LARGE_DEPLOYMENTS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_large_deployment_build_and_deploy(
    ops_test: OpsTest, charm, series, deploy_type: str
) -> None:
    """Build and deploy a large deployment for OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    tls_config = {"ca-common-name": "CN_CA"}

    main_orchestrator_conf = {
        "cluster_name": "plugins-test",
        "init_hold": False,
        "roles": "cluster_manager,data",
    }
    failover_orchestrator_conf = {
        "cluster_name": "plugins-test",
        "init_hold": True,
        "roles": "cluster_manager,data",
    }
    data_hot_conf = {"cluster_name": "plugins-test", "init_hold": True, "roles": "data.hot,ml"}

    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=tls_config
        ),
        ops_test.model.deploy(
            charm,
            application_name=MAIN_ORCHESTRATOR_NAME,
            num_units=1,
            series=series,
            config=main_orchestrator_conf | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            charm,
            application_name=FAILOVER_ORCHESTRATOR_NAME,
            num_units=2,
            series=series,
            config=failover_orchestrator_conf | CONFIG_OPTS,
        ),
        ops_test.model.deploy(
            charm,
            application_name=APP_NAME,
            num_units=1,
            series=series,
            config=data_hot_conf | CONFIG_OPTS,
        ),
    )

    # Large deployment setup
    await ops_test.model.integrate("main:peer-cluster-orchestrator", "failover:peer-cluster")
    await ops_test.model.integrate("main:peer-cluster-orchestrator", f"{APP_NAME}:peer-cluster")
    await ops_test.model.integrate(
        "failover:peer-cluster-orchestrator", f"{APP_NAME}:peer-cluster"
    )

    # TLS setup
    await ops_test.model.integrate(MAIN_ORCHESTRATOR_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(FAILOVER_ORCHESTRATOR_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)

    await _wait_for_units(ops_test, deploy_type)
    await set_watermark(ops_test, APP_NAME)


@pytest.mark.parametrize("deploy_type", LARGE_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_large_deployment_prometheus_exporter_cos_relation(
    ops_test, series, deploy_type: str
):
    # Check that the correct settings were successfully communicated to grafana-agent
    await ops_test.model.deploy(COS_APP_NAME, channel=COS_CHANNEL, series=series),
    await ops_test.model.integrate(FAILOVER_ORCHESTRATOR_NAME, COS_APP_NAME)
    await ops_test.model.integrate(MAIN_ORCHESTRATOR_NAME, COS_APP_NAME)
    await ops_test.model.integrate(APP_NAME, COS_APP_NAME)

    await _wait_for_units(ops_test, deploy_type, wait_for_cos=True)

    leader_id = await get_leader_unit_id(ops_test, APP_NAME)
    leader_name = f"{APP_NAME}/{leader_id}"

    cos_leader_id = await get_leader_unit_id(ops_test, COS_APP_NAME)
    relation_data = await get_unit_relation_data(
        ops_test, f"{COS_APP_NAME}/{cos_leader_id}", leader_name, COS_RELATION_NAME, "config"
    )
    if not isinstance(relation_data, dict):
        relation_data = json.loads(relation_data)
    relation_data = relation_data["metrics_scrape_jobs"][0]
    secret = await get_secret_by_label(ops_test, "opensearch:app:monitor-password")

    assert relation_data["basic_auth"]["username"] == "monitor"
    assert relation_data["basic_auth"]["password"] == secret["monitor-password"]

    admin_secret = await get_secret_by_label(ops_test, "opensearch:app:app-admin")
    assert relation_data["tls_config"]["ca"] == admin_secret["ca-cert"]
    assert relation_data["scheme"] == "https"


@pytest.mark.parametrize("deploy_type", ALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_monitoring_user_fetch_prometheus_data(ops_test, deploy_type: str):
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=APP_NAME)
    endpoint = f"https://{leader_unit_ip}:9200/_prometheus/metrics"

    secret = await get_secret_by_label(ops_test, "opensearch:app:monitor-password")
    response = await http_request(
        ops_test,
        "get",
        endpoint,
        app=APP_NAME,
        json_resp=False,
        user="monitor",
        user_password=secret["monitor-password"],
    )
    response_str = response.content.decode("utf-8")

    assert response_str.count("opensearch_") > 500
    assert len(response_str.split("\n")) > 500


@pytest.mark.parametrize("deploy_type", ALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_prometheus_monitor_user_password_change(ops_test, deploy_type: str):
    # Password change applied as expected
    app = APP_NAME if deploy_type == "small_deployment" else MAIN_ORCHESTRATOR_NAME

    leader_id = await get_leader_unit_id(ops_test, app)
    result1 = await run_action(
        ops_test, leader_id, "set-password", {"username": "monitor"}, app=app
    )
    await _wait_for_units(ops_test, deploy_type, wait_for_cos=True)

    new_password = result1.response.get("monitor-password")
    # Now, we compare the change in the action above with the opensearch's nodes.
    # In large deployments, that will mean checking if the change on main orchestrator
    # was sent down to the opensearch (data node) cluster.
    result2 = await run_action(
        ops_test, leader_id, "get-password", {"username": "monitor"}, app=app
    )
    assert result2.response.get("password") == new_password

    # Relation data is updated
    # In both large and small deployments, we want to check if the relation data is updated
    # on the data node: "opensearch"
    leader_id = await get_leader_unit_id(ops_test, APP_NAME)
    leader_name = f"{APP_NAME}/{leader_id}"

    # We're not sure which grafana-agent is sitting with APP_NAME in large deployments
    cos_leader_id = await get_leader_unit_id(ops_test, COS_APP_NAME)
    relation_data = await get_unit_relation_data(
        ops_test, f"{COS_APP_NAME}/{cos_leader_id}", leader_name, COS_RELATION_NAME, "config"
    )
    if not isinstance(relation_data, dict):
        relation_data = json.loads(relation_data)
    relation_data = relation_data["metrics_scrape_jobs"][0]["basic_auth"]

    assert relation_data["username"] == "monitor"
    assert relation_data["password"] == new_password


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_knn_search_with_hnsw_faiss(ops_test: OpsTest, deploy_type: str) -> None:
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
    docs = await search(ops_test, app, leader_unit_ip, index_name, query, retries=30)
    assert len(docs) == 2


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_knn_search_with_hnsw_nmslib(ops_test: OpsTest, deploy_type: str) -> None:
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
    docs = await search(ops_test, app, leader_unit_ip, index_name, query, retries=30)
    assert len(docs) == 2


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_knn_training_search(ops_test: OpsTest, deploy_type: str) -> None:
    """Tests the entire cycle of KNN plugin.

    1) Enters data and trains a model in "test_end_to_end_with_ivf_faiss_training"
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
    index_name = "test_end_to_end_with_ivf_faiss_training"
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

    query = {
        "size": 2,
        "query": {"knn": {"target-field": {"vector": payload_list[0], "k": 2}}},
    }

    docs = await search(
        ops_test,
        app,
        leader_unit_ip,
        "test_end_to_end_with_ivf_faiss_target",
        query,
        retries=3,
    )
    assert len(docs) == 2, f"Unexpected search results count: {len(docs)}."


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_reports_scheduler(ops_test: OpsTest, deploy_type: str) -> None:
    """Test that the reports scheduler plugin is enabled and functional."""
    # Deploy OpenSearch Dashboards
    await ops_test.model.deploy(
        DASHBOARDS_APP_NAME,
        channel="2/edge",
    )
    await ops_test.model.integrate(DASHBOARDS_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.integrate(DASHBOARDS_APP_NAME, APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[DASHBOARDS_APP_NAME, APP_NAME],
        status="active",
    )
    dashboards_leader_unit_ip = await get_leader_unit_ip(ops_test, app=DASHBOARDS_APP_NAME)
    dashboards_base_url = f"https://{dashboards_leader_unit_ip}:5601"

    # download sample data
    sample_data = "ecommerce"
    logger.info(f"Downloading sample {sample_data} data...")
    response = await http_request(
        ops_test,
        "POST",
        f"{dashboards_base_url}/api/sample_data/{sample_data}",
        extra_headers={"osd-xsrf": "true"},
    )
    logger.info(f"Download response: {response}")
    assert response["opensearchIndicesCreated"], f"Sample data '{sample_data}' not downloaded"

    logger.info("Finding a dashboard..")
    response = await http_request(
        ops_test,
        "GET",
        f"{dashboards_base_url}/api/saved_objects/_find?type=dashboard&search_fields=title&search={sample_data}",
    )
    logger.info(f"Search fields response: {response}")
    dashboard_id = response["saved_objects"][0]["id"]

    start = int(datetime.now(timezone.utc).timestamp() * 1000)
    payload = {
        "reportDefinition": {
            "name": f"{sample_data}-report-definition",
            "isEnabled": True,
            "source": {
                "description": f"{sample_data} report",
                "type": "Dashboard",
                "origin": dashboards_base_url,
                "id": dashboard_id,
            },
            "format": {"duration": "PT12H", "fileFormat": "Pdf"},
            "trigger": {
                "triggerType": "IntervalSchedule",
                "schedule": {"interval": {"start_time": start, "period": 1, "unit": "Minutes"}},
            },
            "delivery": {
                "title": "",
                "textDescription": "",
                "htmlDescription": "",
                "configIds": [],
            },
        }
    }

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
    endpoint = f"{base_url}/_plugins/_reports"

    logger.info("Creating report definition...")
    response = await http_request(ops_test, "POST", f"{endpoint}/definition", payload)

    logger.info(f"Report definition response: {response}")
    report_definition_id = response["reportDefinitionId"]

    logger.info("Wait for schedule interval time to pass...")
    await asyncio.sleep(60)

    logger.info("Poll for report instance creation")
    await poll_until(
        ops_test,
        f"{endpoint}/instances",
        lambda instances: instances.get("totalHits") > 0,
        timeout=60 * 3,
    )

    # fetch report instance
    response = await http_request(ops_test, "GET", f"{endpoint}/instances")
    logger.info(f"Instances {response}")
    assert report_definition_id in [
        instance["reportDefinitionDetails"]["id"] for instance in response["reportInstanceList"]
    ], "Could not find report instance from report definition"

    # delete report definition
    await http_request(ops_test, "DELETE", f"{endpoint}/definition/{report_definition_id}")

    # delete sample data
    await http_request(ops_test, "DELETE", f"{dashboards_base_url}/api/sample_data/{sample_data}")

    # remove dashboards application
    await ops_test.model.remove_application(DASHBOARDS_APP_NAME, block_until_done=True)


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_sql_plugin(ops_test: OpsTest, deploy_type: str) -> None:
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
    logger.info(f"SQL query response: {response}")
    assert response.get("size") == 1, "Unexpected SQL result"
    assert response.get("datarows")[0][-1] == target_text, "Unexpected SQL result"


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_ism_and_job_scheduler_plugins(ops_test: OpsTest, deploy_type: str) -> None:
    """Test that the ISM and job scheduler plugins are enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

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


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_anomaly_detection(ops_test: OpsTest, deploy_type: str) -> None:
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
    anomaly = 1000.0
    docs = []
    for i in range(n):
        timestamp = (start + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")
        value = anomaly if i == 200 else 10.0 + (i % 5)
        docs.append({"timestamp": timestamp, "value": value})

    await bulk_insert(ops_test, APP_NAME, leader_unit_ip, bulk_encode(docs, anomaly_index))
    await http_request(ops_test, "POST", f"{base_url}/{anomaly_index}/_refresh")

    # create detector
    detector = {
        "name": "anomaly-detection",
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
    response = await http_request(ops_test, "POST", detectors_url, detector)
    logger.info(f"Detector creation response {response}")
    detector_id = response.get("_id")
    assert detector_id, "Detector not created"

    # run detector
    start_time = int(start.timestamp() * 1000)
    end_time = int((start + timedelta(minutes=n)).timestamp() * 1000)
    response = await http_request(
        ops_test,
        "POST",
        f"{detectors_url}/{detector_id}/_start",
        {
            "start_time": start_time,
            "end_time": end_time,
        },
    )
    task_id = response.get("_id")
    assert task_id, "Anomaly detection task not created"

    # task will complete almost immediately
    await asyncio.sleep(5)

    payload = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"detector_id": detector_id}},
                    {"range": {"anomaly_grade": {"gt": 0}}},
                    {"term": {"task_id": task_id}},
                ]
            }
        }
    }

    response = await http_request(ops_test, "POST", f"{detectors_url}/results/_search", payload)
    logger.info(f"Anomaly results search response: {response}")
    assert response.get("hits", {}).get("total", {}).get("value", 0) > 0, "No anomalies found"
    assert (
        response.get("hits").get("hits")[0].get("_source").get("feature_data")[0].get("data")
        == anomaly
    ), "Unexpected anomaly result"

    # stop detector
    await http_request(ops_test, "POST", f"{detectors_url}/{detector_id}/_stop")
    await http_request(ops_test, "DELETE", f"{detectors_url}/{detector_id}")
    await delete_index(ops_test, APP_NAME, leader_unit_ip, anomaly_index)


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_async_search_plugin(ops_test: OpsTest, deploy_type: str) -> None:
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
    async_job_id = response.get("id")
    assert async_job_id, "Async search job not created"

    # poll until complete
    logger.info("Waiting for async search job to complete...")
    assert await poll_until(
        ops_test,
        f"{endpoint}/{async_job_id}",
        lambda progress: progress.get("state") == "STORE_RESIDENT",
    ), "Async search did not complete before timeout"


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_alerting_plugin(ops_test: OpsTest, deploy_type: str) -> None:
    """Test that the alerting plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_plugins/_alerting/monitors"

    # create monitor
    payload = {
        "name": "alerting-test",
        "monitor_type": "query_level_monitor",
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
    monitor_id = response.get("_id")
    assert monitor_id, "Alerting monitor not created"

    logger.info(f"Executing alerting monitor {monitor_id}")
    response = await http_request(
        ops_test,
        "POST",
        f"{endpoint}/{monitor_id}/_execute",
        payload={"periodStart": "now-30m", "periodEnd": "now"},
    )

    logger.info(f"Monitor execution response: {response}")
    trigger_results = list(response.get("trigger_results", {}).values())
    assert len(trigger_results) > 0, "No alert trigger results"
    assert trigger_results[0]["triggered"], "Alert not triggered"

    # check alerts
    response = await http_request(
        ops_test,
        "GET",
        f"{base_url}/_plugins/_alerting/monitors/alerts?monitorId={monitor_id}",
    )

    assert response.get("totalAlerts", 0) > 0, "No alerts found"


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_query_insights_plugin(ops_test: OpsTest, deploy_type: str) -> None:
    """Test that the query insights plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    response = await http_request(ops_test, "GET", f"{base_url}/_insights/top_queries")
    assert response.get("top_queries"), "No top queries returned"


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_notifications_plugin(ops_test: OpsTest, deploy_type: str) -> None:
    """Test that the notifications plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    notifications_endpoint = f"{base_url}/_plugins/_notifications"

    response = await http_request(ops_test, "GET", f"{notifications_endpoint}/features")
    assert response.get("allowed_config_type_list")

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
    channel_id = response.get("config_id")
    assert channel_id, "Notification channel not created"
    logger.info(f"Created: {channel_id}")

    # attempt to send test notification
    logger.info(f"Attempting test notification to channel {channel_id} (attempt should fail)")
    response = await http_request(
        ops_test, "GET", f"{notifications_endpoint}/feature/test/{channel_id}"
    )

    logger.info(f"Notifications test response: {response}")
    assert (
        "Failed to send webhook" in response["error"]["reason"]
    ), "Did not attempt to send webhook notification"


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_ml_plugin(ops_test: OpsTest, deploy_type: str) -> None:
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
    assert response.get("status") == "COMPLETED", "ML run did not complete"


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_observability_plugin(ops_test: OpsTest, deploy_type: str) -> None:
    """Test that PPL queries can be interpreted for the observability plugin."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    # send PPL query
    payload = {"query": f"source = {TEST_INDEX}"}
    response = await http_request(ops_test, "POST", f"{base_url}/_plugins/_ppl", payload)
    assert response.get("size") == len(TEST_DOCS)


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_flow_framework_plugin(ops_test: OpsTest, deploy_type: str) -> None:
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
    model_group_id = response.get("model_group_id")
    assert model_group_id, "Model group not created"

    # register model
    payload = TEXT_EMBEDDING_MODEL | {"model_group_id": model_group_id}
    response = await http_request(ops_test, "POST", f"{ml_endpoint}/models/_register", payload)
    task_id = response.get("task_id")
    assert task_id, "Model registration task not created"

    # poll until model registered
    logger.info("Waiting for model registration to complete...")
    assert await poll_until(
        ops_test,
        f"{ml_endpoint}/tasks/{task_id}",
        lambda status: status.get("state") == "COMPLETED",
    ), "ML model registration did not complete before timeout"

    # get model id
    response = await http_request(ops_test, "GET", f"{ml_endpoint}/tasks/{task_id}")
    model_id = response.get("model_id")
    assert model_id, "Model not created"

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
    workflow_id = response.get("workflow_id")
    assert workflow_id, "Workflow not created"

    logger.info("Waiting for flow framework workflow to complete...")
    assert await poll_until(
        ops_test,
        f"{endpoint}/{workflow_id}/_status",
        lambda workflow: workflow.get("state") == "COMPLETED",
    )

    # check if index was created
    resp_code = await http_request(
        ops_test, "GET", f"{base_url}/{TEST_INDEX}", resp_status_code=True
    )
    assert resp_code == 200, "Flow framework did not create index"


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_neural_search_plugin(ops_test: OpsTest, deploy_type: str) -> None:
    """Test that the neural search plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"

    # get model id used for ingesting documents to this index
    # ingest pipeline with id {INGEST_PIPELINE_ID} was created during flow framework test
    response = await http_request(
        ops_test, "GET", f"{base_url}/_ingest/pipeline/{INGEST_PIPELINE_ID}"
    )
    processors = response.get(INGEST_PIPELINE_ID).get("processors", [])
    assert len(processors) > 0
    model_id = processors[0].get("text_embedding").get("model_id")
    assert model_id, "Could not find model for neural search"

    # deploy model
    response = await http_request(
        ops_test, "POST", f"{base_url}/_plugins/_ml/models/{model_id}/_deploy"
    )
    task_id = response.get("task_id")
    assert task_id, "Model deployment task not created"

    # poll until model deployment complete
    logger.info("Waiting for model deployment to complete...")
    assert await poll_until(
        ops_test,
        f"{base_url}/_plugins/_ml/tasks/{task_id}",
        lambda status: status.get("state") == "COMPLETED",
    )

    # insert docs
    await bulk_insert(ops_test, APP_NAME, leader_unit_ip, bulk_encode(TEST_DOCS, TEST_INDEX))
    await http_request(ops_test, "POST", f"{base_url}/{TEST_INDEX}/_refresh")

    # run neural search
    payload = {
        "query": {"neural": {"passage_embedding": {"query_text": "hello", "model_id": model_id}}}
    }
    response = await http_request(ops_test, "GET", f"{base_url}/{TEST_INDEX}/_search", payload)
    assert len(response.get("hits", {}).get("hits", [])) > 0, "Neural search did not yield results"


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_ltr_plugin(ops_test: OpsTest, deploy_type: str) -> None:
    """Test that the learning-to-rank plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_ltr/_featureset"

    # initialize default feature store
    response = await http_request(ops_test, "PUT", f"{base_url}/_ltr")
    assert response.get("acknowledged"), "LTR index not created"

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
    assert response.get("result") == "created", "Feature set not created"

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
    logger.info(f"LTR model creation response: {response}")
    assert response.get("result") == "created", "LTR model not created"

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
    logger.info(f"LTR search response: {response}")
    assert (
        len(response.get("hits", {}).get("hits", [])) == 1
    ), "Scoring with LTR did not yield a result"
    await delete_index(ops_test, APP_NAME, leader_unit_ip, TEST_INDEX)


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_security_analytics_plugin(ops_test: OpsTest, deploy_type: str) -> None:
    """Test that the security analytics plugin is enabled and functional."""
    leader_unit_ip = await get_leader_unit_ip(ops_test)
    base_url = f"https://{leader_unit_ip}:9200"
    endpoint = f"{base_url}/_plugins/_security_analytics"

    # add custom rule to select doc with activity = suspicious
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
    rule_id = response.get("_id")
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
                "name": {"type": "keyword"},
            }
        },
    )

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
    detector_id = response.get("_id")
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
    logger.info("Waiting for security analytics finding to be reported...")
    assert await poll_until(
        ops_test,
        f"{endpoint}/findings/_search?detector_id={detector_id}",
        lambda findings: findings.get("total_findings") == 1,
        timeout=60 * 3,
    )
    await http_request(ops_test, "DELETE", f"{endpoint}/detectors/{detector_id}")
    await http_request(ops_test, "DELETE", f"{endpoint}/rules/{rule_id}?category=linux")
    await delete_index(ops_test, APP_NAME, leader_unit_ip, log_index)


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_custom_codecs_plugin(ops_test: OpsTest, deploy_type: str) -> None:
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


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_geospatial_plugin(ops_test: OpsTest, deploy_type: str) -> None:
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
    logger.info("Waiting for data to be available...")
    assert await poll_until(
        ops_test,
        f"{endpoint}/{datasource}",
        lambda ds: ds["datasources"][0]["state"] == "AVAILABLE",
        timeout=60 * 5,
        interval=10,
    ), "Geo data not available before timeout"

    geo_pipeline = "geo-pipeline"
    payload = {"processors": [{"ip2geo": {"field": "ip", "datasource": datasource}}]}
    await http_request(ops_test, "PUT", f"{base_url}/_ingest/pipeline/{geo_pipeline}", payload)

    # get geo-enriched data
    payload = {"docs": [{"_index": "testindex1", "_id": "1", "_source": {"ip": "172.0.0.1"}}]}
    response = await http_request(
        ops_test, "POST", f"{base_url}/_ingest/pipeline/{geo_pipeline}/_simulate", payload
    )
    logger.info(f"Geospatial response: {response}")

    # ensure geo enriched data exists
    enriched_documents = response.get("docs", [])
    assert len(enriched_documents) > 0, "No geo-enriched documents found"
    assert enriched_documents[0]["doc"]["_source"]["ip2geo"], "No geo-enriched data found"


@pytest.mark.parametrize("deploy_type", SMALL_DEPLOYMENTS)
@pytest.mark.abort_on_fail
async def test_skills_plugin(ops_test: OpsTest, deploy_type: str) -> None:
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
    agent_id = response.get("agent_id")
    assert agent_id, "Flow agent not created"

    # run the agent
    payload = {"parameters": {"question": "How many indices do I have?"}}

    response = await http_request(ops_test, "POST", f"{endpoint}/{agent_id}/_execute", payload)
    assert len(response.get("inference_results", [])) > 0, "Flow agent did not return any results"
