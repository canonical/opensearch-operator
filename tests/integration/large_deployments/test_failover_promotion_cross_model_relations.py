#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging

import pytest
from charms.opensearch.v0.constants_charm import (
    PeerClusterOrchestratorRelationName,
    PeerClusterRelationName,
    PeerRelationName,
)
from charms.opensearch.v0.constants_tls import TLS_RELATION
from charms.opensearch.v0.models import (
    DeploymentDescription,
    DeploymentType,
    PeerClusterOrchestrators,
)
from ops import Model
from pytest_operator.plugin import OpsTest

from ..helpers import CONFIG_OPTS, MODEL_CONFIG
from ..relations.helpers import get_application_relation_data
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)
MAIN_APP = "opensearch-main"
FAILOVER_APP = "opensearch-failover"
DATA_APP = "opensearch-data"

CLUSTER_NAME = "app"

APP_UNITS = {MAIN_APP: 1, FAILOVER_APP: 1, DATA_APP: 1}

MAIN_ORCHESTRATOR_OFFER = "main-integration"
FAILOVER_ORCHESTRATOR_OFFER = "failover-integration"
CERTS_OFFER = "certs-integration"
TIMEOUT = 45 * 60


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(
    ops_test: OpsTest, charm, series, failover_model: Model, data_model: Model
) -> None:
    """Build and deploy one unit of OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(
            charm,
            application_name=MAIN_APP,
            num_units=APP_UNITS[MAIN_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME} | CONFIG_OPTS,
        ),
    )
    await ops_test.model.integrate(MAIN_APP, TLS_CERTIFICATES_APP_NAME)

    await ops_test.model.wait_for_idle(apps=[MAIN_APP, TLS_CERTIFICATES_APP_NAME], timeout=TIMEOUT)
    main_peer_cluster_orchestrator_offer = f"offer {ops_test.model.info.name}.{MAIN_APP}:{PeerClusterOrchestratorRelationName} {MAIN_ORCHESTRATOR_OFFER}"
    logger.info("Offering relations in main model...")
    await ops_test.juju(*main_peer_cluster_orchestrator_offer.split())

    certificates_offer = f"offer {ops_test.model.info.name}.{TLS_CERTIFICATES_APP_NAME}:{TLS_RELATION} {CERTS_OFFER}"
    await ops_test.juju(*certificates_offer.split())

    main_model_name = f"{ops_test.model.info.name}"
    consume_main = f"consume admin/{main_model_name}.{MAIN_ORCHESTRATOR_OFFER}"
    consume_certs = f"consume admin/{main_model_name}.{CERTS_OFFER}"

    with ops_test.model_context("failover"):
        await failover_model.deploy(
            charm,
            application_name=FAILOVER_APP,
            num_units=APP_UNITS[FAILOVER_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True} | CONFIG_OPTS,
        )

        logger.info("Consuming offers in failover model...")
        await ops_test.juju(*consume_main.split())
        await ops_test.juju(*consume_certs.split())
        logger.info("Adding integrations in failover model...")
        await failover_model.integrate(
            f"{FAILOVER_APP}",
            f"{MAIN_ORCHESTRATOR_OFFER}:{PeerClusterOrchestratorRelationName}",
        )
        logger.info("Integrating certs with failover...\n")
        await failover_model.integrate(f"{FAILOVER_APP}", f"{CERTS_OFFER}:{TLS_RELATION}")
        await failover_model.wait_for_idle(apps=[FAILOVER_APP], timeout=TIMEOUT)

        failover_peer_cluster_orchestrator_offer = f"offer {failover_model.info.name}.{FAILOVER_APP}:{PeerClusterOrchestratorRelationName} {FAILOVER_ORCHESTRATOR_OFFER}"
        logger.info("Offering relations from failover model...")
        await ops_test.juju(*failover_peer_cluster_orchestrator_offer.split())

    with ops_test.model_context("data"):
        await data_model.deploy(
            charm,
            application_name=DATA_APP,
            num_units=APP_UNITS[DATA_APP],
            series=series,
            config={"cluster_name": CLUSTER_NAME, "init_hold": True, "roles": "data.hot,ml"}
            | CONFIG_OPTS,
        )

        consume_failover = (
            f"consume admin/{failover_model.info.name}.{FAILOVER_ORCHESTRATOR_OFFER}"
        )
        logger.info("Consuming offers in data model...")
        await ops_test.juju(*consume_main.split())
        await ops_test.juju(*consume_failover.split())
        await ops_test.juju(*consume_certs.split())

        logger.info("Integrating relations in data model...")
        await data_model.integrate(f"{DATA_APP}", f"{CERTS_OFFER}:{TLS_RELATION}")
        await data_model.integrate(
            f"{DATA_APP}",
            f"{MAIN_ORCHESTRATOR_OFFER}:{PeerClusterOrchestratorRelationName}",
        )
        await data_model.integrate(
            f"{DATA_APP}",
            f"{FAILOVER_ORCHESTRATOR_OFFER}:{PeerClusterOrchestratorRelationName}",
        )
        await data_model.wait_for_idle(apps=[DATA_APP], timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_failover_promotion(
    ops_test: OpsTest, failover_model: Model, data_model: Model
) -> None:
    """Test that the failover orchestrator promotes itself

    when the majority of relations with main are severed
    """
    logger.info("Removing failover-main relation...")
    await failover_model.applications[FAILOVER_APP].remove_relation(
        f"{FAILOVER_APP}:{PeerClusterRelationName}",
        f"{MAIN_ORCHESTRATOR_OFFER}:{PeerClusterOrchestratorRelationName}",
    )
    await failover_model.wait_for_idle(
        apps=[FAILOVER_APP],
        raise_on_blocked=False,
    )
    await failover_model.remove_saas(MAIN_ORCHESTRATOR_OFFER)

    with ops_test.model_context("failover"):
        logger.info("Ensuring failover was not promoted...")
        unit = failover_model.applications[FAILOVER_APP].units[-1]
        deployment_desc = await get_application_relation_data(
            ops_test,
            unit_name=unit.name,
            relation_name=PeerRelationName,
            key="deployment-description",
        )
        deployment_desc = DeploymentDescription.from_dict(json.loads(deployment_desc))
        assert deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR

    logger.info("Removing data-main relation...")
    await data_model.applications[DATA_APP].remove_relation(
        f"{DATA_APP}:{PeerClusterRelationName}",
        f"{MAIN_ORCHESTRATOR_OFFER}:{PeerClusterOrchestratorRelationName}",
    )
    await data_model.wait_for_idle(
        apps=[DATA_APP],
        raise_on_blocked=False,
    )
    await data_model.remove_saas(MAIN_ORCHESTRATOR_OFFER)
    with ops_test.model_context("data"):
        logger.info("Ensuring failover was promoted to main...")
        # get orchestrators registered in data app
        unit = data_model.applications[DATA_APP].units[-1]
        orchestrators = await get_application_relation_data(
            ops_test, unit_name=unit.name, relation_name=PeerRelationName, key="orchestrators"
        )
        # ensure failover is the new main and that no failover is registered
        orchestrators = PeerClusterOrchestrators.from_dict(json.loads(orchestrators))
        assert orchestrators.main_app.name == FAILOVER_APP
        assert orchestrators.failover_app is None
