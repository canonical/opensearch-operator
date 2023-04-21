#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import logging
import time

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.ha.continuous_writes import ContinuousWrites
from tests.integration.ha.helpers import (  # get_shards_by_index,; instance_ip,; send_kill_signal_to_process,
    app_name,
    cut_network_from_unit,
    get_controller_machine,
    get_elected_cm_unit,
    get_unit_ip,
    is_machine_reachable_from,
    restore_network_for_unit,
    secondary_up_to_date,
    wait_network_restore,
)

# from tests.integration.ha.helpers_data import (
#     create_index,
#     default_doc,
#     delete_index,
#     index_doc,
#     search,
# )
from tests.integration.ha.test_horizontal_scaling import IDLE_PERIOD
from tests.integration.helpers import (
    get_application_unit_ids_ips,  # ; get_application_unit_names,; get_leader_unit_ip,; is_up,
)
from tests.integration.helpers import (  # check_cluster_formation_successful,;; get_application_unit_ids,# ;; check_cluster_formation_successful,; get_application_unit_ids,; get_application_unit_names,; get_leader_unit_ip,; get_reachable_unit_ips,; is_up,
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ips,
    ping_cluster,
    unit_hostname,
)
from tests.integration.tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


SECOND_APP_NAME = "second-opensearch"


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
    await c_writes.clear()


@pytest.fixture()
async def c_balanced_writes_runner(ops_test: OpsTest, c_writes: ContinuousWrites):
    """Same as previous runner, but starts continuous writes on cluster wide replicated index."""
    await c_writes.start(repl_on_all_nodes=True)
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
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3


async def test_cluster_manager_network_cut(ops_test, c_writes, c_writes_runner):
    """Test that we can cut the network to the cluster manager and the cluster stays online.

    TODO this may require scaling the cluster up to 5 nodes, so we can guarantee 3 functional nodes
    on update.
    TODO try with just one node and see what happens
    """
    # locate cluster manager unit
    app = await app_name(ops_test)
    ip_addresses = get_application_unit_ips(ops_test, app)
    cm = await get_elected_cm_unit(ops_test, ip_addresses[0])
    all_units = ops_test.model.applications[app].units

    cm_hostname = await unit_hostname(ops_test, cm.name)
    cm_address = await get_unit_ip(ops_test, cm.name)
    # verify the cluster works fine before we can test
    # TODO update assertion to check the cluster returns what we expect
    assert await ping_cluster(
        ops_test,
        cm_address,
    ), f"Connection to host {cm_address} is not possible"

    logger.error(
        f"cutting network for unit {cm.name} with address {cm_address} and hostname {cm_hostname}"
    )

    cut_network_from_unit(cm_hostname)

    c_writes.update()

    # verify machine is not reachable from peer units
    for unit in set(all_units) - {cm}:
        hostname = await unit_hostname(ops_test, unit.name)
        assert not is_machine_reachable_from(
            hostname, cm_hostname
        ), f"unit is reachable from peer {unit.name}"

    # verify machine is not reachable from controller
    controller = await get_controller_machine(ops_test)
    assert not is_machine_reachable_from(
        controller, cm_hostname
    ), "unit is reachable from controller"

    # Wait for another unit to be elected cluster manager TODO this may be part of the problem
    await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active")

    # verify new writes are continuing by counting the number of writes before and after a 5 second
    # wait
    writes = await c_writes.count()
    time.sleep(5)
    more_writes = await c_writes.count()
    assert more_writes > writes, "writes not continuing to OpenSearch"

    # verify that a new cluster manager got elected
    ips = get_application_unit_ips(ops_test, app)
    logger.error(ips)
    logger.error(cm_address)
    if cm_address in ips:
        ips.remove(cm_address)
    new_cm = await get_elected_cm_unit(ops_test, ips[0])
    assert new_cm.name != cm.name

    # verify that no writes to the db were missed
    total_expected_writes = await c_writes.stop()
    actual_writes = await c_writes.count()
    logger.error(total_expected_writes)
    assert total_expected_writes.count == actual_writes, "writes to the db were missed."

    # TODO show status here (check if update-status breaks everything before we restore network)
    time.sleep(70)

    # restore network connectivity to old cluster manager
    restore_network_for_unit(cm_hostname)

    # wait until network is reestablished for the unit
    cm_unit_id = int(cm.name.split("/")[1])
    wait_network_restore(ops_test.model.info.name, hostname=cm_hostname, old_ip=cm_address)
    c_writes.update()

    # self healing is performed with update status hook. Status also checks our node roles are
    # correctly configured.
    await ops_test.model.wait_for_idle()
    await ops_test.model.wait_for_idle(
        apps=[app], status="active", timeout=1000, wait_for_exact_units=3, idle_period=35
    )
    # Sometimes juju can take a long time to update network addresses
    c_writes.update()

    # verify we still have connection to the old cluster manager
    logger.error(get_application_unit_ids_ips(ops_test))
    new_ip = get_application_unit_ids_ips(ops_test)[cm_unit_id]
    logger.error(f"attempting connection to {new_ip}")
    assert await ping_cluster(
        ops_test,
        new_ip,
    ), f"Connection to host {new_ip} is not possible"

    # verify that old cluster manager is up to date.
    total_expected_writes = await c_writes.stop()
    assert await secondary_up_to_date(
        ops_test, new_ip, total_expected_writes.count
    ), "secondary not up to date with the cluster after restarting."
    logger.error(ops_test.model.get_status())
    logger.error(await ops_test.model.get_status())


# async def test_primary_shard_network_cut(ops_test, c_writes, c_writes_runner):
#     """Test that we can cut the network to the primary shard and the cluster stays online.

#     TODO this may require scaling the cluster up to 5 nodes, so we can guarantee 3 working nodes
#     on update.
#     """
#     # locate cluster manager unit
#     app = await app_name(ops_test)
#     leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

#     # find unit hosting the primary shard of the index "series-index"
#     shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
#     primary_shard_unit = [shard.unit_id for shard in shards if shard.is_prim][0]

#     logger.error(dir(primary_shard_unit))
#     all_units = ops_test.model.applications[app].units
#     model_name = ops_test.model.info.name

#     primary_hostname = await unit_hostname(ops_test, primary_shard_unit.name)
#     primary_public_address = primary_shard_unit.public_address

#     # verify the cluster works fine before we can test
#     assert await ping_cluster(
#         ops_test,
#         primary_public_address,
#     ), f"Connection to host {primary_public_address} is not possible"

#     logger.error(
#         f"cutting network for unit {primary_shard_unit.name} with address {primary_shard_unit.public_address}"  # noqa
#     )

#     cut_network_from_unit(primary_hostname)

#     time.sleep(30)

#     # verify machine is not reachable from peer units
#     for unit in set(all_units) - {primary_shard_unit}:
#         hostname = await unit_hostname(ops_test, unit.name)
#         assert not is_machine_reachable_from(
#             hostname, primary_hostname
#         ), "unit is reachable from peer"

#     # verify machine is not reachable from controller
#     controller = await get_controller_machine(ops_test)
#     assert not is_machine_reachable_from(
#         controller, primary_hostname
#     ), "unit is reachable from controller"

#     # Wait for another unit to be elected cluster manager TODO this may be part of the problem
#     await ops_test.model.wait_for_idle(apps=[APP_NAME], status="active", timeout=1000)

#     # verify new writes are continuing by counting the number of writes before and after a 5 second # noqa
#     # wait
#     writes = await c_writes.count()
#     time.sleep(5)
#     more_writes = await c_writes.count()
#     assert more_writes > writes, "writes not continuing to OpenSearch"

#     # verify that a new cluster manager got elected
#     ips = get_application_unit_ips(ops_test, app)
#     logger.error(ips)
#     logger.error(primary_public_address)
#     if primary_public_address in ips:
#         ips.remove(primary_public_address)
#     shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
#     new_primary_shard_unit = [shard.unit_id for shard in shards if shard.is_prim][0]
#     assert new_primary_shard_unit.name != primary_shard_unit.name

#     # verify that no writes to the db were missed
#     total_expected_writes = await c_writes.stop()
#     actual_writes = await c_writes.count()
#     logger.error(total_expected_writes)
#     assert total_expected_writes.count == actual_writes, "writes to the db were missed."

#     # restore network connectivity to old cluster manager
#     restore_network_for_unit(primary_hostname)

#     # wait until network is reestablished for the unit
#     wait_network_restore(model_name, primary_hostname, primary_public_address)

#     time.sleep(30)

#     # self healing is performed with update status hook. Status also checks our node roles are
#     # correctly configured.
#     await ops_test.model.wait_for_idle(
#         apps=[app], status="active", timeout=1000, wait_for_exact_units=3
#     )

#     # verify we still have connection to the old cluster manager
#     # fails - can't access opensearch from this node anymore. We can still access networking, but
#     # opensearch is failing to reconnect for one reason or another.
#     new_ip = instance_ip(model_name, primary_hostname)
#     logger.error(f"attempting connection to {new_ip}")
#     assert await ping_cluster(
#         ops_test,
#         new_ip,
#     ), f"Connection to host {new_ip} is not possible"

#     # verify that old cluster manager is up to date.
#     assert await secondary_up_to_date(
#         ops_test, new_ip, total_expected_writes.count
#     ), "secondary not up to date with the cluster after restarting."


# @pytest.mark.abort_on_fail
# async def test_replication_across_members(
#     ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
# ) -> None:
#     """Check consistency, ie write to node, read data from remaining nodes.

#     1. Create index with replica shards equal to number of nodes - 1.
#     2. Index data.
#     3. Query data from all the nodes (all the nodes should contain a copy of the data).
#     """
#     app = (await app_name(ops_test)) or APP_NAME

#     units = get_application_unit_ids_ips(ops_test, app=app)
#     leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

#     # create index with r_shards = nodes - 1
#     index_name = "test_index"
#     await create_index(ops_test, app, leader_unit_ip, index_name, r_shards=len(units) - 1)

#     # index document
#     doc_id = 12
#     await index_doc(ops_test, app, leader_unit_ip, index_name, doc_id)

#     # check that the doc can be retrieved from any node
#     for _, u_ip in units.items():
#         docs = await search(
#             ops_test,
#             app,
#             u_ip,
#             index_name,
#             query={"query": {"term": {"_id": doc_id}}},
#             preference="_only_local",
#         )
#         assert len(docs) == 1
#         assert docs[0]["_source"] == default_doc(index_name, doc_id)

#     await delete_index(ops_test, app, leader_unit_ip, index_name)

#     # continuous writes checks
#     await assert_continuous_writes_consistency(ops_test, c_writes, app)


# @pytest.mark.abort_on_fail
# async def test_kill_db_process_node_with_primary_shard(
#     ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
# ) -> None:
#     """Check cluster can self-heal + data indexed/read when process dies on node with P_shard."""
#     app = (await app_name(ops_test)) or APP_NAME

#     units_ips = get_application_unit_ids_ips(ops_test, app)
#     leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

#     # find unit hosting the primary shard of the index "series-index"
#     shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
#     first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]

#     # Killing the only instance can be disastrous.
#     if len(ops_test.model.applications[app].units) < 2:
#         await ops_test.model.applications[app].add_unit(count=1)
#         await ops_test.model.wait_for_idle(
#             apps=[app],
#             status="active",
#             timeout=1000,
#             idle_period=IDLE_PERIOD,
#         )

#     # Kill the opensearch process
#     await send_kill_signal_to_process(
#         ops_test, app, first_unit_with_primary_shard, signal="SIGKILL"
#     )

#     # verify new writes are continuing by counting the number of writes before and after 5
#     # seconds
#     # should also be plenty for the shard primary reelection to happen
#     writes = await c_writes.count()
#     time.sleep(5)
#     more_writes = await c_writes.count()
#     assert more_writes > writes, "Writes not continuing to DB"

#     # verify that the opensearch service is back running on the old primary unit
#     assert await is_up(
#         ops_test, units_ips[first_unit_with_primary_shard]
#     ), "OpenSearch service hasn't restarted."

#     # fetch unit hosting the new primary shard of the previous index
#     shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
#     units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
#     assert len(units_with_p_shards) == 2
#     for unit_id in units_with_p_shards:
#         assert (
#             unit_id != first_unit_with_primary_shard
#         ), "Primary shard still assigned to the unit where the service was killed."

#     # check that the unit previously hosting the primary shard now hosts a replica
#     units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
#     assert first_unit_with_primary_shard in units_with_r_shards

#     # verify the node with the old primary successfully joined the rest of the fleet
#     assert await check_cluster_formation_successful(
#         ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
#     )

#     # continuous writes checks
#     await assert_continuous_writes_consistency(ops_test, c_writes, app)


# @pytest.mark.abort_on_fail
# async def test_freeze_db_process_node_with_primary_shard(
#     ops_test: OpsTest, c_writes: ContinuousWrites, c_balanced_writes_runner
# ) -> None:
#     """Check cluster can self-heal + data indexed/read on process freeze on node with P_shard."""
#     app = (await app_name(ops_test)) or APP_NAME

#     units_ips = get_application_unit_ids_ips(ops_test, app)
#     leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)

#     # find unit hosting the primary shard of the index "series-index"
#     shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)
#     first_unit_with_primary_shard = [shard.unit_id for shard in shards if shard.is_prim][0]

#     # Killing the only instance can be disastrous.
#     if len(ops_test.model.applications[app].units) < 2:
#         await ops_test.model.applications[app].add_unit(count=1)
#         await ops_test.model.wait_for_idle(
#             apps=[app],
#             status="active",
#             timeout=1000,
#             idle_period=IDLE_PERIOD,
#         )

#     # Freeze the opensearch process
#     opensearch_pid = await send_kill_signal_to_process(
#         ops_test, app, first_unit_with_primary_shard, signal="SIGSTOP"
#     )

#     # verify the unit is not reachable
#     is_node_up = await is_up(ops_test, units_ips[first_unit_with_primary_shard], retries=3)
#     assert not is_node_up

#     # verify new writes are continuing by counting the number of writes before and after 5
#     # seconds
#     # should also be plenty for the shard primary reelection to happen
#     writes = await c_writes.count()
#     time.sleep(5)
#     more_writes = await c_writes.count()
#     assert more_writes > writes, "writes not continuing to DB"

#     # get reachable unit to perform requests against, in case the previously stopped unit
#     # is leader unit, so its address is not reachable
#     reachable_ip = get_reachable_unit_ips(ops_test)[0]

#     # fetch unit hosting the new primary shard of the previous index
#     shards = await get_shards_by_index(ops_test, reachable_ip, ContinuousWrites.INDEX_NAME)
#     units_with_p_shards = [shard.unit_id for shard in shards if shard.is_prim]
#     assert len(units_with_p_shards) == 2
#     for unit_id in units_with_p_shards:
#         assert (
#             unit_id != first_unit_with_primary_shard
#         ), "Primary shard still assigned to the unit where the service was stopped."

#     # Un-Freeze the opensearch process in the node previously hosting the primary shard
#     await send_kill_signal_to_process(
#         ops_test,
#         app,
#         first_unit_with_primary_shard,
#         signal="SIGCONT",
#         opensearch_pid=opensearch_pid,
#     )

#     # verify that the opensearch service is back running on the unit previously hosting the
#     # p_shard
#     assert await is_up(
#         ops_test, units_ips[first_unit_with_primary_shard]
#     ), "OpenSearch service hasn't restarted."

#     # fetch unit hosting the new primary shard of the previous index
#     shards = await get_shards_by_index(ops_test, leader_unit_ip, ContinuousWrites.INDEX_NAME)

#     # check that the unit previously hosting the primary shard now hosts a replica
#     units_with_r_shards = [shard.unit_id for shard in shards if not shard.is_prim]
#     assert first_unit_with_primary_shard in units_with_r_shards

#     # verify the node with the old primary successfully joined back the rest of the fleet
#     assert await check_cluster_formation_successful(
#         ops_test, leader_unit_ip, get_application_unit_names(ops_test, app=app)
#     )

#     # continuous writes checks
#     await assert_continuous_writes_consistency(ops_test, c_writes, app)


# # put this test at the end of the list of tests, as we delete an app during cleanup
# # and the safeguards we have on the charm prevent us from doing so, so we'll keep
# # using a unit without need - when other tests may need the unit on the CI
# async def test_multi_clusters_db_isolation(
#     ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner
# ) -> None:
#     """Check that writes in cluster not replicated to another cluster."""
#     app = (await app_name(ops_test)) or APP_NAME

#     # remove 1 unit (for CI)
#     unit_ids = get_application_unit_ids(ops_test, app=app)
#     await ops_test.model.applications[app].destroy_unit(f"{app}/{max(unit_ids)}")
#     await ops_test.model.wait_for_idle(
#         apps=[app],
#         status="active",
#         timeout=1000,
#         wait_for_exact_units=len(unit_ids) - 1,
#         idle_period=IDLE_PERIOD,
#     )

#     index_name = "test_index_unique_cluster_dbs"

#     # index document in the current cluster
#     main_app_leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
#     await index_doc(ops_test, app, main_app_leader_unit_ip, index_name, doc_id=1)

#     # deploy new cluster
#     my_charm = await ops_test.build_charm(".")
#     await ops_test.model.deploy(my_charm, num_units=1, application_name=SECOND_APP_NAME)
#     await ops_test.model.relate(SECOND_APP_NAME, TLS_CERTIFICATES_APP_NAME)
#     await ops_test.model.wait_for_idle(apps=[SECOND_APP_NAME], status="active")

#     # index document in second cluster
#     second_app_leader_ip = await get_leader_unit_ip(ops_test, app=SECOND_APP_NAME)
#     await index_doc(ops_test, SECOND_APP_NAME, second_app_leader_ip, index_name, doc_id=2)

#     # fetch all documents in each cluster
#     current_app_docs = await search(ops_test, app, main_app_leader_unit_ip, index_name)
#     second_app_docs = await search(ops_test, SECOND_APP_NAME, second_app_leader_ip, index_name)

#     # check that the only doc indexed in each cluster is different
#     assert len(current_app_docs) == 1
#     assert len(second_app_docs) == 1
#     assert current_app_docs[0] != second_app_docs[0]

#     # cleanup
#     await delete_index(ops_test, app, main_app_leader_unit_ip, index_name)
#     await ops_test.model.remove_application(SECOND_APP_NAME)

#     # continuous writes checks
#     await assert_continuous_writes_consistency(ops_test, c_writes, app)
