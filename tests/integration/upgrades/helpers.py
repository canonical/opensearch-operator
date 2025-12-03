#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import re
import subprocess
import time
from typing import Optional

import pytest
from pytest_operator.plugin import OpsTest
from tenacity import Retrying, stop_after_attempt, wait_fixed

from ..ha.helpers import storage_id
from ..helpers import CONFIG_OPTS, cluster_health, http_request, run_action
from ..helpers_deployments import get_application_units, wait_until, wait_until_unit

OPENSEARCH_CHARM = "opensearch"
OPENSEARCH_CHANNEL = "2/edge"
PROFILES_REVISION = 185

TIMEOUT = 2400
IDLE_PERIOD = 30
FAST_INTERVAL = "60s"

VERSION_N = "2.19.4"
VERSION_N_MINUS_1 = "2.18.0"
VERSION_N_MINUS_2 = "2.17.0"

VERSION_TO_REVISION = {
    VERSION_N_MINUS_2: {"jammy": 168, "noble": 206},
    VERSION_N_MINUS_1: {"jammy": 209, "noble": 208},
}

FROM_VERSION_PREFIX = "from_v{}_to_local"

UPGRADE_PARAMS = [
    pytest.param(
        version,
        id=FROM_VERSION_PREFIX.format(version),
        marks=pytest.mark.group(
            id="two_version_upgrade" if version == VERSION_N_MINUS_2 else "one_version_upgrade"
        ),
    )
    for version in VERSION_TO_REVISION.keys()
]

logger = logging.getLogger(__name__)


def testing_config_if_supported(revision: int) -> dict[str, str]:
    """Returns 'testing' profile config if given revision supports profiles"""
    return CONFIG_OPTS if revision >= PROFILES_REVISION else {}


def refresh(
    ops_test: OpsTest,
    app_name: str,
    *,
    revision: Optional[int] = None,
    switch: Optional[str] = None,
    channel: Optional[str] = None,
    path: Optional[str] = None,
    config: Optional[dict[str, str]] = None,
) -> None:
    # due to: https://github.com/juju/python-libjuju/issues/1057
    # the following call does not work:
    # application = ops_test.model.applications[APP_NAME]
    # await application.refresh(
    #     revision=rev,
    # )

    # Point to the right model, as we are calling the juju cli directly
    args = [f"--model={ops_test.model.info.name}"]
    if revision:
        args.append(f"--revision={revision}")
    if switch:
        args.append(f"--switch={switch}")
    if channel:
        args.append(f"--channel={channel}")
    if path:
        args.append(f"--path={path}")
    if config:
        for key, val in config.items():
            args.extend(["--config", f"{key}={val}"])

    for attempt in Retrying(stop=stop_after_attempt(6), wait=wait_fixed(wait=30)):
        with attempt:
            cmd = ["juju", "refresh"]
            cmd.append(app_name)
            cmd.extend(args)
            subprocess.check_output(cmd)


def get_version_on_unit(unit: str, model: str):
    """Returns version of OpenSearch running on given unit"""
    # opensearch.opensearch-bin not exposed in older snap revisions
    cmd = [
        "juju",
        "exec",
        "--model",
        model,
        "--unit",
        unit,
        "--",
        "sudo",
        "snap",
        "run",
        "--shell",
        "opensearch.daemon",
        "-c",
        "$OPENSEARCH_BIN/opensearch --version",
    ]
    output = subprocess.check_output(cmd, text=True)
    match = re.search(r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+)", output)
    return match.group(1) if match else None


async def assert_version_units(ops_test: OpsTest, app: str, expected_version: str):
    """Ensures all units in given app are running expected OpenSearch version"""
    logger.info(f"Ensuring units in '{app}' running version {expected_version}")

    units = [f"{app}/{unit.id}" for unit in await get_application_units(ops_test, app)]
    versions = [get_version_on_unit(unit, ops_test.model.info.name) for unit in units]
    assert all(
        version == expected_version for version in versions
    ), f"Expected {expected_version} on all units, found versions: {list(zip(units, versions))}"
    logger.info(f"All units in '{app}' running version {expected_version}")


async def assert_upgrade_to_revision(
    ops_test: OpsTest,
    app: str,
    revision: int,
    config: dict[str, str] = {},
):
    """Upgrades app to revision"""
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    # run pre-upgrade-check action on leader
    action = await run_action(ops_test, leader_id, "pre-upgrade-check", app=app)
    logger.info(f"pre-upgrade-check: {action}")
    assert action.status == "completed"

    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        logger.info(f"Refreshing '{app}' to revision {revision}")
        refresh(
            ops_test,
            app,
            revision=revision,
            config=testing_config_if_supported(revision) | config,
        )

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                app: len(units),
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        # run resume-upgrade action on leader
        action = await run_action(ops_test, leader_id, "resume-upgrade", app=app)
        logger.info(f"resume-upgrade: {action}")
        assert action.status == "completed"

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info(f"Upgrade of '{app}' completed")


async def assert_upgrade_to_local(
    ops_test: OpsTest, app: str, charm: str, config: dict[str, str] = {}
):
    """Upgrades to local charm"""
    units = await get_application_units(ops_test, app)
    leader_id = [u.id for u in units if u.is_leader][0]

    # run pre-upgrade-check action on leader
    action = await run_action(ops_test, leader_id, "pre-upgrade-check", app=app)
    logger.info(f"pre-upgrade-check: {action}")
    assert action.status == "completed"

    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        logger.info(f"Refreshing '{app}' local charm")
        refresh(ops_test, app, path=charm, config=CONFIG_OPTS | config)

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                app: len(units),
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        # run resume-upgrade action on leader
        action = await run_action(ops_test, leader_id, "resume-upgrade", app=app)
        logger.info(f"resume-upgrade: {action}")
        assert action.status == "completed"

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info(f"Upgrade of '{app}' completed")


async def assert_rollback_to_revision(
    ops_test: OpsTest,
    app: str,
    charm: str,
    revision: int,
    config: dict[str, str] = {},
):
    """Upgrades to local charm and rolls back to revision mid-upgrade"""
    units = await get_application_units(ops_test, app)
    highest_unit_name = sorted([unit.name for unit in units])[-1]
    highest_unit_ip = [unit.ip for unit in units if unit.name == highest_unit_name][0]
    leader_id = [unit.id for unit in units if unit.is_leader][0]
    nodes = await http_request(
        ops_test,
        "GET",
        f"https://{highest_unit_ip}:9200/_cat/nodes?format=json",
    )
    cluster_size = len(nodes)
    rolled_back_node = None
    for node in nodes:
        if node["ip"] == highest_unit_ip:
            rolled_back_node = node["name"]

    assert rolled_back_node, "Could not determine node name"

    # run pre-upgrade-check action on leader
    action = await run_action(ops_test, leader_id, "pre-upgrade-check", app=app)
    logger.info(f"pre-upgrade-check: {action}")
    assert action.status == "completed"

    n_units = len(units)
    async with ops_test.fast_forward(fast_interval=FAST_INTERVAL):
        logger.info(f"Refreshing '{app}' to local charm")
        refresh(ops_test, app, path=charm, config=CONFIG_OPTS | config)

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["blocked"],
            units_statuses=["active"],
            wait_for_exact_units={
                app: n_units,
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )

        # switch to store charm
        refresh(
            ops_test,
            app,
            switch=OPENSEARCH_CHARM,
            channel=OPENSEARCH_CHANNEL,
            config=CONFIG_OPTS | config,
        )

        time.sleep(5)
        # roll back to revision
        logger.info(f"Rolling back '{app}' to revision: {revision}")
        refresh(
            ops_test,
            app,
            revision=revision,
            config=testing_config_if_supported(revision) | config,
        )

        logger.info("Waiting for rolled back unit to attempt restart...")
        await wait_until_unit(
            ops_test,
            app=app,
            expected_units_with_status=1,
            unit_status="Waiting for OpenSearch to start...",
            timeout=TIMEOUT,
        )

        await recover_from_rollback(ops_test, app, rolled_back_node, cluster_size)

        await wait_until(
            ops_test,
            apps=[app],
            apps_statuses=["active"],
            units_statuses=["active"],
            wait_for_exact_units={
                app: n_units,
            },
            timeout=TIMEOUT,
            idle_period=IDLE_PERIOD,
        )
        logger.info(f"Recovery from rollback of '{app}' completed")


async def recover_from_rollback(
    ops_test: OpsTest, app: str, rolled_back_node: str, expected_cluster_size: int
):
    """Recover from refreshing back mid-upgrade"""
    units = await get_application_units(ops_test, app)
    highest_unit_id = sorted([unit.id for unit in units])[-1]
    unit_ip = [unit.ip for unit in units if unit.id != highest_unit_id][0]

    # re-enable allocation
    logger.info("Re-enabling cluster routing allocation")
    await http_request(
        ops_test,
        "PUT",
        f"https://{unit_ip}:9200/_cluster/settings",
        payload={"persistent": {"cluster.routing.allocation.enable": "all"}},
    )

    time.sleep(5)

    # get health
    cluster_health_resp = await cluster_health(ops_test, unit_ip)
    logger.info(f"Cluster health response: {cluster_health_resp["status"]}")
    if cluster_health_resp["status"] == "red":
        # identify problematic index
        shards = await http_request(
            ops_test,
            "GET",
            f"https://{unit_ip}:9200/_cat/shards?format=json&h=index,shard,state,unassigned.reason",
        )

        indices = set()
        for shard in shards:
            if (
                shard.get("state") == "UNASSIGNED"
                and shard.get("unassigned.reason") == "NODE_LEFT"
            ):
                indices.add(shard.get("index"))

        # delete the indices
        logger.info(f"Unassigned indices: {indices}")
        for index in indices:
            await http_request(
                ops_test,
                "DELETE",
                f"https://{unit_ip}:9200/{index}",
            )

        cluster_health_resp = await cluster_health(ops_test, unit_ip)
        logger.info(
            f"Cluster health response after removing indices: {cluster_health_resp["status"]}"
        )
    # add unit
    logger.info("Adding new unit")
    await ops_test.model.applications[app].add_unit(count=1)

    # wait for new unit to be idle
    await ops_test.model.wait_for_idle(
        apps=[app], wait_for_at_least_units=len(units), timeout=TIMEOUT
    )

    # destroy highest unit
    logger.info(f"Destroying unit `{app}/{highest_unit_id}`")
    await ops_test.model.applications[app].destroy_unit(f"{app}/{highest_unit_id}")

    lock_doc = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/.charm_node_lock/_doc/0",
    )

    # check if lock with departed unit
    logger.info(f"Rolled back OpenSearch node: {rolled_back_node}")
    if lock_doc.get("found") and lock_doc.get("_source").get("unit-name") == rolled_back_node:
        logger.info("Deleting lock document")
        lock_doc = await http_request(
            ops_test,
            "DELETE",
            f"https://{unit_ip}:9200/.charm_node_lock/_doc/0?refresh=true",
        )

    # wait for new unit to be idle
    await ops_test.model.wait_for_idle(
        apps=[app], wait_for_at_least_units=len(units), timeout=TIMEOUT
    )

    # verify node joined cluster
    nodes = await http_request(
        ops_test,
        "GET",
        f"https://{unit_ip}:9200/_cat/nodes?format=json",
    )
    logger.info(f"Nodes in cluster: {", ".join([node["name"] for node in nodes])}")
    assert (
        len(nodes) == expected_cluster_size
    ), f"Expected cluster size of {expected_cluster_size} but found {len(nodes)}"

    remaining_units = await get_application_units(ops_test, app)
    if len(remaining_units) > len(units):
        # force-remove rolled back unit if initial removal not successful
        unit_storage_id = storage_id(ops_test, app, highest_unit_id)
        logger.info(f"Force-removing unit `{app}/{highest_unit_id}`")
        await ops_test.model.destroy_unit(f"{app}/{highest_unit_id}", force=True)
        await ops_test.model.remove_storage(unit_storage_id)
