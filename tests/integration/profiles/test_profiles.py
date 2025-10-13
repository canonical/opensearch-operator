# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import asyncio
import logging

import pytest
from charms.opensearch.v0.constants_charm import PClusterNoDataNode
from pytest_operator.plugin import OpsTest
from requests import request

from ..ha.test_large_deployments_cluster_manager_only_nodes import REL_ORCHESTRATOR
from ..ha.test_large_deployments_relations import REL_PEER
from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)

_3CM_AND_3DATA_MISSING_STATUS = (
    "Missing requirements: At least 3 cluster manager nodes and 3 data nodes are required."
)


async def get_cloud_type(ops_test: OpsTest) -> str:
    """Return current cloud type of the selected controller.

    Args:
        ops_test (OpsTest): ops_test plugin

    Returns:
        string: current type of the underlying cloud
    """
    assert ops_test.model, "Model must be present"
    controller = await ops_test.model.get_controller()
    cloud = await controller.cloud()
    return cloud.cloud.type_


async def get_constraints(ops_test: OpsTest) -> str | None:
    """Get constraints for the OpenSearch charm based on the cloud type."""
    cloud_type = await get_cloud_type(ops_test)
    if cloud_type == "lxd":
        return "mem=8G"
    return None


async def check_heap_size(ops_test: OpsTest, heap_size_in_gb: int, app_name: str = APP_NAME):
    """A dummy test to make pytest happy when all other tests are skipped."""
    os_app = ops_test.model.applications[app_name]
    unit = os_app.units[0]

    action = await unit.run_action("get-password")
    action = await action.wait()
    assert action.status == "completed", f"Action failed: {action.error_message}"
    secrets = action.results
    assert secrets is not None
    password = secrets.get("password")
    assert password is not None, "Password should not be None"

    # request the OpenSearch endpoint to get the JVM settings
    jvm_response = request(
        "GET",
        f"https://{unit.public_address}:9200/_nodes/stats/jvm",
        verify=False,
        auth=("admin", password),
    )
    assert jvm_response.status_code == 200, f"Failed to get JVM stats: {jvm_response.text}"
    jvm_info = jvm_response.json()
    assert "nodes" in jvm_info, "No nodes information in JVM stats"
    for node_id, node_info in jvm_info["nodes"].items():
        assert "jvm" in node_info, f"No JVM information for node {node_id}"
        jvm_mem = node_info["jvm"]["mem"]
        heap_max_in_bytes = jvm_mem["heap_max_in_bytes"]
        # Check that the heap size is set to 4GB (in bytes)
        assert (
            heap_max_in_bytes == heap_size_in_gb * 1024 * 1024 * 1024
        ), f"Heap size is not {heap_size_in_gb}GB: {heap_max_in_bytes}"


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, charm, series) -> None:
    """Build and deploy one unit of OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)
    constraints = await get_constraints(ops_test)
    logger.info(f"Using constraints: {constraints}")
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(
            charm,
            num_units=1,
            series=series,
            constraints=constraints,
            config={"profile": "production"},
        ),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)


@pytest.mark.abort_on_fail
async def test_wait_blocked_cluster_topology(ops_test: OpsTest) -> None:
    """Wait for blocked cluster with cluster topology error"""
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_full_statuses={APP_NAME: {"blocked": [_3CM_AND_3DATA_MISSING_STATUS]}},
        units_full_statuses={APP_NAME: {"units": {"blocked": [_3CM_AND_3DATA_MISSING_STATUS]}}},
        wait_for_exact_units=1,
    )


@pytest.mark.abort_on_fail
async def test_scale_to_active(ops_test: OpsTest) -> None:
    """Scale the OpenSearch cluster to the active state."""
    os_app = ops_test.model.applications[APP_NAME]
    await os_app.add_units(count=2)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        wait_for_exact_units=3,
    )

    await check_heap_size(ops_test, 4)


@pytest.mark.abort_on_fail
async def test_insufficient_memory(ops_test: OpsTest, charm: str, series: str) -> None:
    """Test insufficient memory scenario."""
    cloud_name = await get_cloud_type(ops_test)
    if cloud_name != "lxd":
        pytest.skip("This test is only applicable for LXD cloud type")

    if APP_NAME in ops_test.model.applications:
        await ops_test.model.remove_application(APP_NAME, block_until_done=True)

    await ops_test.model.deploy(
        charm,
        num_units=3,
        series=series,
        constraints="mem=3G",
        config={"profile": "production"},
    )
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    # we do not wait for idle in this wait because the 3 units will keep trying
    # to acquire the lock but it will always be given to leader who cannot start
    # because it is blocked and deferring
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_full_statuses={
            APP_NAME: {
                "blocked": ["Missing requirements: Insufficient memory: 3145728.0 < 8388608"]
            }
        },
        units_full_statuses={
            APP_NAME: {
                "units": {
                    "blocked": [
                        "Missing requirements: Insufficient memory: 3145728.0 < 8388608",
                    ],
                }
            }
        },
        wait_for_exact_units=3,
    )


@pytest.mark.abort_on_fail
async def test_testing_profile(ops_test: OpsTest, charm: str, series: str) -> None:
    """Test testing profile"""
    if APP_NAME in ops_test.model.applications:
        await ops_test.model.remove_application(APP_NAME, block_until_done=True)
    constraints = await get_constraints(ops_test)

    await ops_test.model.deploy(
        charm, num_units=1, series=series, config={"profile": "testing"}, constraints=constraints
    )
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=1,
    )
    await check_heap_size(ops_test, 1)


@pytest.mark.abort_on_fail
async def test_config_changed_to_production(ops_test: OpsTest) -> None:
    os_app = ops_test.model.applications[APP_NAME]
    await os_app.set_config({"profile": "production"})
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_full_statuses={APP_NAME: {"blocked": [_3CM_AND_3DATA_MISSING_STATUS]}},
        units_full_statuses={APP_NAME: {"units": {"blocked": [_3CM_AND_3DATA_MISSING_STATUS]}}},
        wait_for_exact_units=1,
    )


@pytest.mark.abort_on_fail
async def test_large_deployment_cluster(ops_test: OpsTest, charm: str, series: str) -> None:
    """Test large deployment cluster scenario."""
    if APP_NAME in ops_test.model.applications:
        await ops_test.model.remove_application(APP_NAME, block_until_done=True)
    constraints = await get_constraints(ops_test)
    await ops_test.model.deploy(
        charm,
        application_name="main",
        num_units=1,
        series=series,
        config={"cluster_name": "test", "roles": "cluster_manager", "profile": "production"},
        constraints=constraints,
    )
    await ops_test.model.deploy(
        charm,
        application_name="data",
        num_units=1,
        series=series,
        config={
            "cluster_name": "test",
            "init_hold": True,
            "roles": "data",
            "profile": "production",
        },
        constraints=constraints,
    )

    # integrate TLS to all applications
    for app in ["main", "data"]:
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    # create the peer-cluster-relation
    await ops_test.model.integrate(f"data:{REL_PEER}", f"main:{REL_ORCHESTRATOR}")

    await wait_until(
        ops_test,
        apps=["main", "data"],
        units_full_statuses={
            "main": {"units": {"blocked": [_3CM_AND_3DATA_MISSING_STATUS]}},
            "data": {"units": {"blocked": [_3CM_AND_3DATA_MISSING_STATUS]}},
        },
        wait_for_exact_units={"main": 1, "data": 1},
    )

    main_app = ops_test.model.applications["main"]
    await main_app.add_units(count=2)

    await wait_until(
        ops_test,
        apps=["main", "data"],
        units_full_statuses={
            "main": {
                "units": {
                    "blocked": [
                        "Missing requirements: At least 3 data nodes are required.",
                        PClusterNoDataNode,
                    ]
                }
            },
            "data": {
                "units": {
                    "blocked": [
                        "Missing requirements: At least 3 data nodes are required.",
                    ]
                }
            },
        },
        wait_for_exact_units={"main": 3, "data": 1},
    )
    data_app = ops_test.model.applications["data"]
    await data_app.add_units(count=2)
    await wait_until(ops_test, apps=["main", "data"], wait_for_exact_units=3, timeout=2000)

    await check_heap_size(ops_test, 4, app_name="main")
