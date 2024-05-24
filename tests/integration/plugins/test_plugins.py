#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import json
import logging

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import RetryError

from ..ha.helpers import app_name
from ..ha.helpers_data import bulk_insert, create_index, search
from ..ha.test_horizontal_scaling import IDLE_PERIOD
from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    check_cluster_formation_successful,
    get_application_unit_ids_ips,
    get_application_unit_names,
    get_leader_unit_id,
    get_leader_unit_ip,
    get_secret_by_label,
    http_request,
    run_action,
)
from ..helpers_deployments import wait_until
from ..plugins.helpers import (
    create_index_and_bulk_insert,
    generate_bulk_training_data,
    get_application_unit_ids_start_time,
    is_each_unit_restarted,
    is_knn_training_complete,
    run_knn_training,
)
from ..relations.helpers import get_unit_relation_data
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME

COS_APP_NAME = "grafana-agent"
COS_RELATION_NAME = "cos-agent"


logger = logging.getLogger(__name__)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy an OpenSearch cluster."""
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")

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
            my_charm, num_units=3, series=SERIES, config={"plugin_opensearch_knn": True}
        ),
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={TLS_CERTIFICATES_APP_NAME: 1, APP_NAME: 3},
        timeout=3400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.abort_on_fail
@pytest.mark.group(1)
async def test_prometheus_exporter_enabled_by_default(ops_test):
    """Test that Prometheus Exporter is running before the relation is there."""
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=APP_NAME)
    endpoint = f"https://{leader_unit_ip}:9200/_prometheus/metrics"
    response = await http_request(ops_test, "get", endpoint, app=APP_NAME, json_resp=False)

    response_str = response.content.decode("utf-8")
    assert response_str.count("opensearch_") > 500
    assert len(response_str.split("\n")) > 500


@pytest.mark.abort_on_fail
@pytest.mark.group(1)
async def test_prometheus_exporter_cos_relation(ops_test):
    await ops_test.model.deploy(COS_APP_NAME, channel="edge"),
    await ops_test.model.integrate(APP_NAME, COS_APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=3,
        idle_period=IDLE_PERIOD,
    )

    # Check that the correct settings were successfully communicated to grafana-agent
    cos_leader_id = await get_leader_unit_id(ops_test, COS_APP_NAME)
    cos_leader_name = f"{COS_APP_NAME}/{cos_leader_id}"
    leader_id = await get_leader_unit_id(ops_test, APP_NAME)
    leader_name = f"{APP_NAME}/{leader_id}"
    relation_data_raw = await get_unit_relation_data(
        ops_test, cos_leader_name, leader_name, COS_RELATION_NAME, "config"
    )
    relation_data = json.loads(relation_data_raw)["metrics_scrape_jobs"][0]
    secret = await get_secret_by_label(ops_test, "opensearch:app:monitor-password")

    assert relation_data["basic_auth"]["username"] == "monitor"
    assert relation_data["basic_auth"]["password"] == secret["monitor-password"]

    admin_secret = await get_secret_by_label(ops_test, "opensearch:app:app-admin")
    assert relation_data["tls_config"]["ca"] == admin_secret["ca-cert"]
    assert relation_data["scheme"] == "https"


@pytest.mark.abort_on_fail
@pytest.mark.group(1)
async def test_monitoring_user_fetch_prometheus_data(ops_test):
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


@pytest.mark.abort_on_fail
@pytest.mark.group(1)
async def test_prometheus_monitor_user_password_change(ops_test):
    # Password change applied as expected
    leader_id = await get_leader_unit_id(ops_test, APP_NAME)
    result1 = await run_action(ops_test, leader_id, "set-password", {"username": "monitor"})
    new_password = result1.response.get("monitor-password")
    result2 = await run_action(ops_test, leader_id, "get-password", {"username": "monitor"})

    assert result2.response.get("password") == new_password

    # Relation data is updated
    cos_leader_id = await get_leader_unit_id(ops_test, COS_APP_NAME)
    cos_leader_name = f"{COS_APP_NAME}/{cos_leader_id}"
    leader_id = await get_leader_unit_id(ops_test, APP_NAME)
    leader_name = f"{APP_NAME}/{leader_id}"
    relation_data_raw = await get_unit_relation_data(
        ops_test, cos_leader_name, leader_name, COS_RELATION_NAME, "config"
    )
    relation_data = json.loads(relation_data_raw)["metrics_scrape_jobs"][0]["basic_auth"]
    assert relation_data["username"] == "monitor"
    assert relation_data["password"] == new_password


@pytest.mark.abort_on_fail
@pytest.mark.group(1)
async def test_knn_enabled_disabled(ops_test):
    config = await ops_test.model.applications[APP_NAME].get_config()
    assert config["plugin_opensearch_knn"]["default"] is True
    assert config["plugin_opensearch_knn"]["value"] is True

    async with ops_test.fast_forward():
        await ops_test.model.applications[APP_NAME].set_config({"plugin_opensearch_knn": "False"})
        await wait_until(
            ops_test,
            apps=[APP_NAME],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units={APP_NAME: 3},
            timeout=3600,
            idle_period=IDLE_PERIOD,
        )

        config = await ops_test.model.applications[APP_NAME].get_config()
        assert config["plugin_opensearch_knn"]["value"] is False

        await ops_test.model.applications[APP_NAME].set_config({"plugin_opensearch_knn": "True"})
        await wait_until(
            ops_test,
            apps=[APP_NAME],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units={APP_NAME: 3},
            timeout=3600,
            idle_period=IDLE_PERIOD,
        )

        config = await ops_test.model.applications[APP_NAME].get_config()
        assert config["plugin_opensearch_knn"]["value"] is True

        await wait_until(
            ops_test,
            apps=[APP_NAME],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units={APP_NAME: 3},
            timeout=3600,
            idle_period=IDLE_PERIOD,
        )


@pytest.mark.group(1)
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
    docs = await search(ops_test, app, leader_unit_ip, index_name, query, retries=30)
    assert len(docs) == 2


@pytest.mark.group(1)
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
    docs = await search(ops_test, app, leader_unit_ip, index_name, query, retries=30)
    assert len(docs) == 2


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_knn_training_search(ops_test: OpsTest) -> None:
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

    # Set the config to false, then to true
    for knn_enabled in [False, True]:
        logger.info(f"KNN test starting with {knn_enabled}")

        # get current timestamp, to compare with restarts later
        ts = await get_application_unit_ids_start_time(ops_test, APP_NAME)
        await ops_test.model.applications[APP_NAME].set_config(
            {"plugin_opensearch_knn": str(knn_enabled)}
        )

        await wait_until(
            ops_test,
            apps=[APP_NAME],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units={APP_NAME: 3},
            timeout=3600,
            idle_period=IDLE_PERIOD,
        )

        # Now use it to compare with the restart
        assert await is_each_unit_restarted(ops_test, APP_NAME, ts)
        assert await check_cluster_formation_successful(
            ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=APP_NAME)
        ), "Restart happened but cluster did not start correctly"
        logger.info("Restart finished and was successful")

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
