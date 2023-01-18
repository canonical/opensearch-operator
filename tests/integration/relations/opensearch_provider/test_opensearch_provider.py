#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import logging

import pytest
from charms.opensearch.v0.constants_charm import ClientRelationName
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import APP_NAME, UNIT_IDS

logger = logging.getLogger(__name__)

CLIENT_APP_NAME = "application"
NUM_UNITS = len(UNIT_IDS)


@pytest.mark.abort_on_fail
@pytest.mark.client_relation
async def test_database_relation_with_charm_libraries(
    ops_test: OpsTest, application_charm, opensearch_charm
):
    """Test basic functionality of database relation interface."""
    # Deploy both charms (multiple units for each application to test that later they correctly
    # set data in the relation application databag using only the leader unit).
    await asyncio.gather(
        ops_test.model.deploy(
            application_charm,
            application_name=CLIENT_APP_NAME,
        ),
        ops_test.model.deploy(
            opensearch_charm,
            application_name=APP_NAME,
            num_units=NUM_UNITS,
        ),
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            timeout=1000, status="blocked", num_units=NUM_UNITS + 1
        )  # Add one for client app

    # Relate the charms and wait for them exchanging some connection data.
    global client_relation
    client_relation = await ops_test.model.add_relation(
        f"{APP_NAME}:{ClientRelationName}", f"{CLIENT_APP_NAME}:database"
    )

    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(timeout=1000, status="blocked")
