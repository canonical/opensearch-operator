#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import logging

import pytest
from charms.opensearch.v0.constants_charm import ClientRelationName
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import APP_NAME, MODEL_CONFIG, SERIES, UNIT_IDS
from tests.integration.relations.opensearch_provider.helpers import (
    wait_for_relation_joined_between,
)

logger = logging.getLogger(__name__)

CLIENT_APP_NAME = "application"
NUM_UNITS = len(UNIT_IDS)

TLS_CERTIFICATES_APP_NAME = "tls-certificates-operator"


@pytest.mark.abort_on_fail
@pytest.mark.client_relation
async def test_database_relation_with_charm_libraries(
    ops_test: OpsTest, application_charm, opensearch_charm
):
    """Test basic functionality of database relation interface."""
    # Deploy both charms (multiple units for each application to test that later they correctly
    # set data in the relation application databag using only the leader unit).
    await ops_test.model.set_config(MODEL_CONFIG)
    tls_config = {"generate-self-signed-certificates": "true", "ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            application_charm,
            application_name=CLIENT_APP_NAME,
        ),
        ops_test.model.deploy(
            opensearch_charm, application_name=APP_NAME, num_units=NUM_UNITS, series=SERIES
        ),
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="edge", config=tls_config),
    )

    # Relate TLS to OpenSearch to set up TLS.
    # NOTE in future we need to make sure we can deploy all relations simultaneously since this
    #      will happen simultaneously in bundles, but for now, make sure opensearch and TLS are
    #      active before adding client relation.
    await ops_test.model.relate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    wait_for_relation_joined_between(ops_test, APP_NAME, TLS_CERTIFICATES_APP_NAME)
    async with ops_test.fast_forward():
        await asyncio.gather(
            # TODO why does this take so long?
            ops_test.model.wait_for_idle(
                apps=[APP_NAME, TLS_CERTIFICATES_APP_NAME], status="active", timeout=900
            ),
            ops_test.model.wait_for_idle(apps=[CLIENT_APP_NAME], status="blocked", timeout=900),
        )

    # Relate the charms and wait for them exchanging some connection data.
    # TODO this doesn't need to be a variable right now, but it will be in future.
    global client_relation
    client_relation = await ops_test.model.add_relation(
        f"{APP_NAME}:{ClientRelationName}", f"{CLIENT_APP_NAME}:first-database"
    )

    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(timeout=600, status="active")
