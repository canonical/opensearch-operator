#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging

import pytest
from charms.opensearch.v0.constants_charm import (
    PeerRelationName,
)
from charms.opensearch.v0.models import (
    PeerClusterOrchestrators,
)
from pytest_operator.plugin import OpsTest

from ..helpers import CONFIG_OPTS, MODEL_CONFIG
from ..helpers_deployments import wait_until
from ..relations.helpers import get_application_relation_data
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)
MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"
DATA_APP_TWO = "opensearch-data-two"

CLUSTER_NAME = "app"

APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 1, DATA_APP: 1, DATA_APP_TWO: 1}


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, charm, series) -> None:
    """Build and deploy one unit of OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)

    await ops_test.model.create_storage_pool("local", "lxd", "volume-type=standard")

    # Deploy TLS Certificates operator.
    tls_config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=tls_config
        ),
        ops_test.model.deploy(
            charm,
            application_name=MAIN_APP,
            num_units=APP_UNITS[MAIN_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager,data"} | CONFIG_OPTS,
            storage={"opensearch-data": "local,128G,1"},
        ),
        ops_test.model.deploy(
            charm,
            application_name=FAILOVER_APP,
            num_units=APP_UNITS[FAILOVER_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "roles": "cluster_manager", "init_hold": True}
            | CONFIG_OPTS,
            storage={"opensearch-data": "local,128G,1"},
        ),
        ops_test.model.deploy(
            charm,
            application_name=DATA_APP,
            num_units=APP_UNITS[DATA_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "roles": "data", "init_hold": True}
            | CONFIG_OPTS,
            storage={"opensearch-data": "local,128G,1"},
        ),
        ops_test.model.deploy(
            charm,
            application_name=DATA_APP_TWO,
            num_units=APP_UNITS[DATA_APP_TWO],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "roles": "data", "init_hold": True}
            | CONFIG_OPTS,
            storage={"opensearch-data": "local,128G,1"},
        ),
    )
    for app in APP_UNITS:
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    for app in [FAILOVER_APP, DATA_APP, DATA_APP_TWO]:
        await ops_test.model.integrate(
            f"{MAIN_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster"
        )

    for app in [DATA_APP, DATA_APP_TWO]:
        await ops_test.model.integrate(
            f"{FAILOVER_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster"
        )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_APP_TWO, TLS_CERTIFICATES_APP_NAME],
        apps_statuses=["active"],
        units_full_statuses={
            MAIN_APP: {"units": {"active": []}},
            DATA_APP: {"units": {"active": []}},
            FAILOVER_APP: {"units": {"active": []}},
            DATA_APP_TWO: {"units": {"active": []}},
            TLS_CERTIFICATES_APP_NAME: {"units": {"active": []}},
        },
        wait_for_exact_units=1,
    )


@pytest.mark.abort_on_fail
async def test_check_orchestrators_in_rel_data(ops_test: OpsTest) -> None:
    """Test that the orchestrators are correctly set."""
    data_app = ops_test.model.applications[DATA_APP]
    assert data_app is not None
    orchestrators = await get_application_relation_data(
        ops_test,
        unit_name=data_app.units[0].name,
        relation_name=PeerRelationName,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == MAIN_APP
    ), "Main orchestrator not set correctly"
    assert (
        orchestrators.failover_app and orchestrators.failover_app.name == FAILOVER_APP
    ), "Failover orchestrator not set correctly"


@pytest.mark.abort_on_fail
async def test_demotion_through_relation_removal(ops_test: OpsTest) -> None:
    """Test that removing the main orchestrator relations demotes it and promotes the failover."""
    main_app = ops_test.model.applications[MAIN_APP]
    assert main_app is not None

    for app in [FAILOVER_APP, DATA_APP, DATA_APP_TWO]:
        await main_app.remove_relation(
            f"{MAIN_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster"
        )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_APP_TWO],
        apps_full_statuses={
            MAIN_APP: {"active": []},
            FAILOVER_APP: {"active": []},
            DATA_APP: {"active": []},
            DATA_APP_TWO: {"active": []},
        },
        units_full_statuses={
            MAIN_APP: {"units": {"active": []}},
            FAILOVER_APP: {"units": {"active": []}},
            DATA_APP: {"units": {"active": []}},
            DATA_APP_TWO: {"units": {"active": []}},
        },
        wait_for_exact_units=1,
    )

    # check that failover was promoted to main orchestrator
    data_app = ops_test.model.applications[DATA_APP]
    assert data_app is not None
    orchestrators = await get_application_relation_data(
        ops_test,
        unit_name=data_app.units[0].name,
        relation_name=PeerRelationName,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == FAILOVER_APP
    ), "Failover was not promoted to main orchestrator"
    assert (
        orchestrators.failover_app is None
    ), "Failover orchestrator should be None after promotion"


@pytest.mark.abort_on_fail
async def test_failover_election_after_restoring_integration(ops_test: OpsTest) -> None:
    """Test that the failover orchestrator is correctly elected after re-adding relations."""
    await ops_test.model.integrate(
        f"{FAILOVER_APP}:peer-cluster-orchestrator", f"{MAIN_APP}:peer-cluster"
    )
    for app in [DATA_APP, DATA_APP_TWO]:
        await ops_test.model.integrate(
            f"{MAIN_APP}:peer-cluster-orchestrator", f"{app}:peer-cluster"
        )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, DATA_APP_TWO],
        apps_statuses=["active"],
        units_full_statuses={
            MAIN_APP: {"units": {"active": []}},
            DATA_APP: {"units": {"active": []}},
            DATA_APP_TWO: {"units": {"active": []}},
        },
        wait_for_exact_units=1,
    )

    # check that main app is now elected failover orchestrator
    data_app = ops_test.model.applications[DATA_APP]
    assert data_app is not None
    orchestrators = await get_application_relation_data(
        ops_test,
        unit_name=data_app.units[0].name,
        relation_name=PeerRelationName,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == FAILOVER_APP
    ), "Failover is supposed to be the main orchestrator"
    assert (
        orchestrators.failover_app and orchestrators.failover_app.name == MAIN_APP
    ), "Main app is supposed to be the failover orchestrator"


@pytest.mark.abort_on_fail
async def test_scale_promoted_main_to_0_then_up(ops_test: OpsTest) -> None:
    """Test scaling main orchestrator to 0 and back to 1 unit."""
    # Main orchestrator is the failover app at this point
    failover_app = ops_test.model.applications[FAILOVER_APP]
    assert failover_app is not None

    storages = await ops_test.model.list_storage()
    failover_app_storages = [
        s["storage-tag"] for s in storages if failover_app.units[0].tag in s["attachments"]
    ]
    logger.info(f"Failover app storages: {failover_app_storages}")
    await failover_app.destroy_unit(failover_app.units[0].name)

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, DATA_APP_TWO],
        apps_full_statuses={
            MAIN_APP: {"active": []},
            DATA_APP: {"active": []},
            DATA_APP_TWO: {"active": []},
        },
        units_full_statuses={
            MAIN_APP: {"units": {"active": []}},
            DATA_APP: {"units": {"active": []}},
            DATA_APP_TWO: {"units": {"active": []}},
        },
        wait_for_exact_units=1,
    )

    # check that main app is now elected main orchestrator and that failover is None
    data_app = ops_test.model.applications[DATA_APP]
    assert data_app is not None
    orchestrators = await get_application_relation_data(
        ops_test,
        unit_name=data_app.units[0].name,
        relation_name=PeerRelationName,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == MAIN_APP
    ), "Main app is supposed to be the main orchestrator"
    assert (
        orchestrators.failover_app is None
    ), "Failover app is supposed to be None since there is no failover orchestrator"

    # scale back to 1 unit
    await failover_app.add_unit(attach_storage=failover_app_storages)
    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, FAILOVER_APP, DATA_APP_TWO],
        apps_full_statuses={
            MAIN_APP: {
                "waiting": [
                    "Waiting for peer cluster relation to be created in related 'failover-orchestrator'."
                ]
            },
            FAILOVER_APP: {"blocked": ["Cannot start. Waiting for peer cluster relation..."]},
            DATA_APP: {
                "waiting": [
                    "Waiting for peer cluster relation to be created in related 'failover-orchestrator'."
                ]
            },
            DATA_APP_TWO: {
                "waiting": [
                    "Waiting for peer cluster relation to be created in related 'failover-orchestrator'."
                ]
            },
        },
        units_full_statuses={
            MAIN_APP: {"units": {"active": []}},
            FAILOVER_APP: {"units": {"active": []}},
            DATA_APP: {
                "units": {"active": ["Missing requirements: At least 1 data nodes are required."]}
            },
            DATA_APP_TWO: {"units": {"active": []}},
        },
    )

    await failover_app.remove_relation(
        f"{FAILOVER_APP}:peer-cluster-orchestrator", f"{MAIN_APP}:peer-cluster"
    )

    await ops_test.model.integrate(
        f"{MAIN_APP}:peer-cluster-orchestrator", f"{FAILOVER_APP}:peer-cluster"
    )

    await wait_until(
        ops_test,
        apps=[MAIN_APP, DATA_APP, DATA_APP_TWO],
        apps_full_statuses={
            MAIN_APP: {"active": []},
            FAILOVER_APP: {"active": []},
            DATA_APP: {"active": []},
            DATA_APP_TWO: {"active": []},
        },
        units_full_statuses={
            MAIN_APP: {"units": {"active": []}},
            DATA_APP: {"units": {"active": []}},
            DATA_APP_TWO: {"units": {"active": []}},
        },
        wait_for_exact_units=1,
    )

    # check that main app is still elected main orchestrator and that failover is the failover app
    orchestrators = await get_application_relation_data(
        ops_test,
        unit_name=data_app.units[0].name,
        relation_name=PeerRelationName,
        key="orchestrators",
    )
    assert orchestrators, "No orchestrators found in relation data"
    orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
    assert (
        orchestrators.main_app and orchestrators.main_app.name == MAIN_APP
    ), "Main app is supposed to be the main orchestrator"
    assert (
        orchestrators.failover_app and orchestrators.failover_app.name == FAILOVER_APP
    ), "Failover app is supposed to be the failover orchestrator"
