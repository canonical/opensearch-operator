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
    run_knn_training,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

COS_APP_NAME = "grafana-agent"


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


async def test_prometheus_exporter_disabled_by_default(ops_test):
    # Test that Prometheus Exporter is NOT running before the relation is there
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=APP_NAME)
    endpoint = f"https://{leader_unit_ip}:9200/_prometheus/metrics"
    response = await http_request(ops_test, "get", endpoint, app=APP_NAME)
    assert response == {
        "error": "no handler found for uri [/_prometheus/metrics] and method [GET]"
    }


async def test_prometheus_exporter_enabled_by_cos_relation(ops_test):
    await ops_test.model.deploy(COS_APP_NAME, channel="edge"),
    await ops_test.model.relate(APP_NAME, COS_APP_NAME)
    # NOTE: As for now, COS agent remains blocked, as we only have a partial config
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    config = await ops_test.model.applications[APP_NAME].get_config()
    assert config["prometheus_exporter_plugin_url"]["default"].startswith("https://")

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=APP_NAME)
    endpoint = f"https://{leader_unit_ip}:9200/_prometheus/metrics"
    response = await http_request(ops_test, "get", endpoint, app=APP_NAME, json_resp=False)

    response_str = response.content.decode("utf-8")
    assert response_str.count("opensearch_") > 500
    assert len(response_str.split("\n")) > 500


async def test_prometheus_exporter_disabled_by_cos_relation_gone(ops_test):
    await ops_test.juju("remove-relation", APP_NAME, COS_APP_NAME)

    # Wait 90s as the update-status is supposed to happen every 1m
    # If model config is updated, update this routine as well.
    await asyncio.sleep(150)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )

    leader_unit_ip = await get_leader_unit_ip(ops_test, app=APP_NAME)
    endpoint = f"https://{leader_unit_ip}:9200/_prometheus/metrics"
    response = await http_request(ops_test, "get", endpoint, app=APP_NAME)
    assert response == {
        "error": "no handler found for uri [/_prometheus/metrics] and method [GET]"
    }


async def test_knn_endabled_disabled(ops_test):
    config = await ops_test.model.applications[APP_NAME].get_config()
    assert config["plugin_opensearch_knn"]["default"] is False
    assert config["plugin_opensearch_knn"]["value"] is True

    await ops_test.model.applications[APP_NAME].set_config({"plugin_opensearch_knn": "False"})
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", idle_period=15)

    config = await ops_test.model.applications[APP_NAME].get_config()
    assert config["plugin_opensearch_knn"]["value"] is False

    await ops_test.model.applications[APP_NAME].set_config({"plugin_opensearch_knn": "True"})
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", idle_period=15)

    config = await ops_test.model.applications[APP_NAME].get_config()
    assert config["plugin_opensearch_knn"]["value"] is True


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
