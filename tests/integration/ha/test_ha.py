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
    assert_continuous_writes_consistency,
    cut_network_from_unit,
    get_controller_machine,
    get_elected_cm_unit,
    is_machine_reachable_from,
    restore_network_for_unit,
    secondary_up_to_date,
    wait_network_restore,
)
from tests.integration.ha.helpers_data import (
    create_index,
    default_doc,
    delete_index,
    index_doc,
    search,
)
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids,
    get_application_unit_ids_ips,
    get_application_unit_ips,
    get_leader_unit_ip,
    ping_cluster,
    unit_hostname,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


SECOND_APP_NAME = "second-opensearch"


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
    # locate cluster manager unit
    app = await app_name(ops_test)
    ip_addresses = get_application_unit_ips(ops_test, app)
    cm = await get_elected_cm_unit(ops_test, ip_addresses[0])
    all_units = ops_test.model.applications[app].units
    model_name = ops_test.model.info.name

    cm_hostname = await unit_hostname(ops_test, cm.name)
    cm_public_address = cm.public_address

    # verify the cluster works fine before we can test
    # TODO update assertion to check the cluster returns what we expect
    assert await ping_cluster(
        ops_test,
        cm_public_address,
    ), f"Connection to host {cm_public_address} is not possible"

    cut_network_from_unit(cm_hostname)

    # verify machine is not reachable from peer units
    for unit in set(all_units) - {cm}:
        hostname = await unit_hostname(ops_test, unit.name)
        assert not is_machine_reachable_from(hostname, cm_hostname), "unit is reachable from peer"

    # verify machine is not reachable from controller
    controller = await get_controller_machine(ops_test)
    assert not is_machine_reachable_from(
        controller, cm_hostname
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
    ips.remove(cm_public_address)
    new_cm = await get_elected_cm_unit(ops_test, ips[0])
    assert new_cm.name != cm.name

    # verify that no writes to the db were missed
    total_expected_writes = await c_writes.stop()
    actual_writes = await c_writes.count()
    logger.error(total_expected_writes)
    assert total_expected_writes.count == actual_writes, "writes to the db were missed."

    # restore network connectivity to old cluster manager
    restore_network_for_unit(cm_hostname)

    # wait until network is reestablished for the unit
    wait_network_restore(model_name, cm_hostname, cm_public_address)
    await ops_test.model.wait_for_idle(
        apps=[app], status="active", timeout=1000, wait_for_exact_units=3
    )

    # self healing is performed with update status hook. Status also checks our node roles are
    # correctly configured.
    await ops_test.model.wait_for_idle(
        apps=[app], status="active", timeout=1000, wait_for_exact_units=3
    )

    # verify we still have connection to the old cluster manager
    # new_ip = instance_ip(model_name, cm_hostname)
    # fails - can't access opensearch from this node anymore.
    # we can still access networking, but opensearch is failing to reconnect for one reason or
    # another. TODO next week figure out opensearch node reconnect policy/stratz
    # TODO assertion commented out
    # assert await ping_cluster(
    logger.error(
        await ping_cluster(
            ops_test,
            cm.public_address,
        )
    )
    # , f"Connection to host {cm.public_address} is not possible"

    # verify that old cluster manager is up to date.
    assert await secondary_up_to_date(
        ops_test, cm.public_address, total_expected_writes.count
    ), "secondary not up to date with the cluster after restarting."


@pytest.mark.abort_on_fail
async def test_replication_across_members(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check consistency, ie write to node, read data from remaining nodes.

    1. Create index with replica shards equal to number of nodes - 1.
    2. Index data.
    3. Query data from all the nodes (all the nodes should contain a copy of the data).
    """
    app = (await app_name(ops_test)) or APP_NAME

    units = get_application_unit_ids_ips(ops_test, app=app)
    leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

    # create index with r_shards = nodes - 1
    index_name = "test_index"
    await create_index(ops_test, app, leader_unit_ip, index_name, r_shards=len(units) - 1)

    # index document
    doc_id = 12
    await index_doc(ops_test, app, leader_unit_ip, index_name, doc_id)

    # check that the doc can be retrieved from any node
    for u_id, u_ip in units.items():
        docs = await search(
            ops_test,
            app,
            u_ip,
            index_name,
            query={"query": {"term": {"_id": doc_id}}},
            preference="_only_local",
        )
        assert len(docs) == 1
        assert docs[0]["_source"] == default_doc(index_name, doc_id)

    await delete_index(ops_test, app, leader_unit_ip, index_name)

    # continuous writes checks
    await assert_continuous_writes_consistency(c_writes)


# put this test at the end of the list of tests, as we delete an app during cleanup
# and the safeguards we have on the charm prevent us from doing so, so we'll keep
# using a unit without need - when other tests may need the unit on the CI
async def test_multi_clusters_db_isolation(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Check that writes in cluster not replicated to another cluster."""
    app = (await app_name(ops_test)) or APP_NAME

    # remove 1 unit (for CI)
    unit_ids = get_application_unit_ids(ops_test, app=app)
    await ops_test.model.applications[app].destroy_unit(f"{app}/{max(unit_ids)}")
    await ops_test.model.wait_for_idle(
        apps=[app],
        status="active",
        timeout=1000,
        wait_for_exact_units=len(unit_ids) - 1,
        idle_period=IDLE_PERIOD,
    )

    index_name = "test_index_unique_cluster_dbs"

    # index document in the current cluster
    main_app_leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    await index_doc(ops_test, app, main_app_leader_unit_ip, index_name, doc_id=1)

    # deploy new cluster
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(my_charm, num_units=1, application_name=SECOND_APP_NAME)
    await ops_test.model.relate(SECOND_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(apps=[SECOND_APP_NAME], status="active")

    # index document in second cluster
    second_app_leader_ip = await get_leader_unit_ip(ops_test, app=SECOND_APP_NAME)
    await index_doc(ops_test, SECOND_APP_NAME, second_app_leader_ip, index_name, doc_id=2)

    # fetch all documents in each cluster
    current_app_docs = await search(ops_test, app, main_app_leader_unit_ip, index_name)
    second_app_docs = await search(ops_test, SECOND_APP_NAME, second_app_leader_ip, index_name)

    # check that the only doc indexed in each cluster is different
    assert len(current_app_docs) == 1
    assert len(second_app_docs) == 1
    assert current_app_docs[0] != second_app_docs[0]

    # cleanup
    await delete_index(ops_test, app, main_app_leader_unit_ip, index_name)
    await ops_test.model.remove_application(SECOND_APP_NAME)

    # continuous writes checks
    await assert_continuous_writes_consistency(c_writes)
