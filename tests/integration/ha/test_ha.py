#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
import time

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (
    app_name,
    cut_network_from_unit,
    get_controller_machine,
    get_elected_cm_unit,
    instance_ip,
    is_machine_reachable_from,
    restore_network_for_unit,
    secondary_up_to_date,
    wait_network_restore,
)
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ips,
    ping_cluster,
    unit_hostname,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)

IDLE_PERIOD = 120


@pytest.fixture()
def c_writes(ops_test: OpsTest):
    """Creates instance of the ContinuousWrites."""
    return ContinuousWrites(ops_test)


@pytest.fixture()
async def c_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Starts continuous write operations and clears writes at the end of the test."""
    await c_writes.start()
    yield
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
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="edge", config=config),
        ops_test.model.deploy(my_charm, num_units=3, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME], status="active", timeout=1000
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


async def test_network_cut(ops_test, c_writes, c_writes_runner):
    """Test that we can cut the network and the cluster stays online as expected.

    TODO this may require scaling the cluster up to 5 nodes, so we can guarantee 3 functional nodes
    on update.
    """
    # locate primary unit
    app = await app_name(ops_test)
    ip_addresses = get_application_unit_ips(ops_test, app)
    primary = await get_elected_cm_unit(ops_test, ip_addresses[0])
    all_units = ops_test.model.applications[app].units
    model_name = ops_test.model.info.name

    primary_hostname = await unit_hostname(ops_test, primary.name)

    # verify the cluster works fine before we can test
    # TODO update assertion to check the cluster returns what we expect
    assert await ping_cluster(
        ops_test,
        primary.public_address,
    ), f"Connection to host {primary.public_address} is not possible"

    cut_network_from_unit(primary_hostname)

    # verify machine is not reachable from peer units
    for unit in set(all_units) - {primary}:
        hostname = await unit_hostname(ops_test, unit.name)
        assert not is_machine_reachable_from(
            hostname, primary_hostname
        ), "unit is reachable from peer"

    # verify machine is not reachable from controller
    controller = await get_controller_machine(ops_test)
    assert not is_machine_reachable_from(
        controller, primary_hostname
    ), "unit is reachable from controller"

    # Wait for another unit to be elected cluster manager
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "writes not continuing to DB"

    # verify that a new cluster manager got elected
    ips = get_application_unit_ips(ops_test, app)
    ips.remove(primary.public_address)
    new_primary = await get_elected_cm_unit(ops_test, ips[0])
    assert new_primary.name != primary.name

    # verify that no writes to the db were missed
    total_expected_writes = await c_writes.stop()
    actual_writes = await c_writes.count()
    logger.error(total_expected_writes)

    assert total_expected_writes.count == actual_writes, "writes to the db were missed."

    # restore network connectivity to old primary
    restore_network_for_unit(primary_hostname)

    # wait until network is reestablished for the unit
    wait_network_restore(model_name, primary_hostname, primary.public_address)
    await ops_test.model.wait_for_idle(apps=[app], status="active", timeout=1000, wait_for_exact_units=3)

    # self healing is performed with update status hook. Status also checks our node roles are
    # correctly configured.
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(apps=[app], status="active", timeout=1000)

    # verify we still have connection to the old primary
    new_ip = instance_ip(model_name, primary_hostname)
    assert await ping_cluster(
        ops_test,
        new_ip,
    ), f"Connection to host {new_ip} is not possible"

    # verify that old primary is up to date.
    assert await secondary_up_to_date(
        ops_test, new_ip, total_expected_writes.count
    ), "secondary not up to date with the cluster after restarting."
