#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import random
import time

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    app_name,
    storage_id,
    storage_type,
    update_restart_delay,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids,
    get_reachable_unit_ips,
    http_request,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


SECOND_APP_NAME = "second-opensearch"
ORIGINAL_RESTART_DELAY = 20
RESTART_DELAY = 360


@pytest.fixture()
async def reset_restart_delay(ops_test: OpsTest):
    """Resets service file delay on all units."""
    yield
    app = (await app_name(ops_test)) or APP_NAME
    for unit_id in get_application_unit_ids(ops_test, app):
        await update_restart_delay(ops_test, app, unit_id, ORIGINAL_RESTART_DELAY)


@pytest.fixture()
async def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    app = (await app_name(ops_test)) or APP_NAME
    return ContinuousWrites(ops_test, app)


@pytest.fixture()
async def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield

    reachable_ip = random.choice(await get_reachable_unit_ips(ops_test))
    await http_request(ops_test, "GET", f"https://{reachable_ip}:9200/_cat/nodes", json_resp=False)
    await http_request(
        ops_test, "GET", f"https://{reachable_ip}:9200/_cat/shards", json_resp=False
    )

    await c_writes.clear()


@pytest.fixture()
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    await c_writes.start(repl_on_all_nodes=True)
    yield

    reachable_ip = random.choice(await get_reachable_unit_ips(ops_test))
    await http_request(ops_test, "GET", f"https://{reachable_ip}:9200/_cat/nodes", json_resp=False)
    await http_request(
        ops_test, "GET", f"https://{reachable_ip}:9200/_cat/shards", json_resp=False
    )

    await c_writes.clear()


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config),
        ops_test.model.deploy(my_charm, num_units=1, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1000,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


@pytest.mark.abort_on_fail
async def test_storage_reuse_after_scale_down(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
):
    """Check storage is reused and data accessible after scaling down and up."""
    app = (await app_name(ops_test)) or APP_NAME

    if storage_type(ops_test, app) == "rootfs":
        pytest.skip(
            "re-use of storage can only be used on deployments with persistent storage not on rootfs deployments"
        )

    # wait for enough data to be written
    time.sleep(60)
    writes_result = await c_writes.stop()

    # get unit info
    unit_id = get_application_unit_ids(ops_test, app)[0]
    unit_storage_id = storage_id(ops_test, app, unit_id)

    # scale-down to 0
    await ops_test.model.applications[app].destroy_unit(f"{app}/{unit_id}")
    await ops_test.model.wait_for_idle(
        apps=[app], status="active", timeout=1000, wait_for_exact_units=0
    )

    # add unit with storage attached
    add_unit_cmd = (
        f"add-unit {app} --model={ops_test.model.info.name} --attach-storage={unit_storage_id}"
    )
    return_code, _, _ = await ops_test.juju(*add_unit_cmd.split())
    assert return_code == 0, "Failed to add unit with storage"

    await ops_test.model.wait_for_idle(
        apps=[app], status="active", timeout=1000, wait_for_exact_units=1
    )

    # check the storage of the new unit
    new_unit_id = get_application_unit_ids(ops_test, app)[0]
    new_unit_storage_id = storage_id(ops_test, app, new_unit_id)
    assert unit_storage_id == new_unit_storage_id, "Storage IDs mismatch."

    # check if data is also imported
    assert writes_result.count == (await c_writes.count())
    assert writes_result.max_stored_id == (await c_writes.max_stored_id())


@pytest.mark.abort_on_fail
async def test_storage_reuse_in_new_cluster_after_app_removal(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
):
    """Check storage is reused and data accessible after removing app and deploying new cluster."""
    app = (await app_name(ops_test)) or APP_NAME

    if storage_type(ops_test, app) == "rootfs":
        pytest.skip(
            "re-use of storage can only be used on deployments with persistent storage not on rootfs deployments"
        )

    # wait for enough data to be written
    time.sleep(60)
    writes_result = await c_writes.stop()

    # get unit info
    storage_ids = []
    for unit_id in get_application_unit_ids(ops_test, app):
        storage_ids.append(storage_id(ops_test, app, unit_id))

    # remove application
    await ops_test.model.applications[app].destroy()

    # deploy new cluster
    my_charm = await ops_test.build_charm(".")
    deploy_cluster_with_storage_cmd = (
        f"deploy {my_charm} --model={ops_test.model.info.name} --attach-storage={storage_ids[0]}"
    )
    return_code, _, _ = await ops_test.juju(*deploy_cluster_with_storage_cmd.split())
    assert return_code == 0, f"Failed to deploy app with storage {storage_ids[0]}"

    # add unit with storage attached
    for unit_storage_id in storage_ids[1:]:
        add_unit_cmd = (
            f"add-unit {app} --model={ops_test.model.info.name} --attach-storage={unit_storage_id}"
        )
        return_code, _, _ = await ops_test.juju(*add_unit_cmd.split())
        assert return_code == 0, f"Failed to add unit with storage {unit_storage_id}"

    await ops_test.model.relate(app, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1000,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[app].units) == 3

    # check if previous volumes are attached to the units of the new cluster
    new_storage_ids = []
    for unit_id in get_application_unit_ids(ops_test, app):
        new_storage_ids.append(storage_id(ops_test, app, unit_id))

    assert sorted(storage_ids) == sorted(new_storage_ids), "Storage IDs mismatch."

    # check if data is also imported
    assert writes_result.count == (await c_writes.count())
    assert writes_result.max_stored_id == (await c_writes.max_stored_id())
