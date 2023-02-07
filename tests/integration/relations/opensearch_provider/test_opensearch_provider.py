#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging

import pytest
from charms.opensearch.v0.constants_charm import ClientRelationName
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import APP_NAME as OPENSEARCH_APP_NAME
from tests.integration.helpers import (  # , scale_application
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
)
from tests.integration.relations.opensearch_provider.helpers import (
    get_application_relation_data,
    run_request_on_application_charm,
    wait_for_relation_joined_between,
)

logger = logging.getLogger(__name__)

CLIENT_APP_NAME = "application"
SECONDARY_CLIENT_APP_NAME = "secondary-application"
TLS_CERTIFICATES_APP_NAME = "tls-certificates-operator"
ALL_APPS = [OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME, CLIENT_APP_NAME]
FIRST_DATABASE_RELATION_NAME = "first-database"

NUM_UNITS = len(UNIT_IDS)


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
            opensearch_charm,
            application_name=OPENSEARCH_APP_NAME,
            num_units=NUM_UNITS,
            series=SERIES,
        ),
        ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="edge", config=tls_config),
    )

    # Relate TLS to OpenSearch to set up TLS.
    # NOTE in future we need to make sure we can deploy all relations simultaneously since this
    #      will happen simultaneously in bundles, but for now, make sure opensearch and TLS are
    #      active before adding client relation.
    await ops_test.model.relate(OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    # async with ops_test.fast_forward():
    #     await asyncio.gather(
    #         # TODO why does this take so long?
    #         ops_test.model.wait_for_idle(
    #             apps=[OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME],
    #             status="active",
    #             timeout=900
    #         ),
    #         ops_test.model.wait_for_idle(apps=[CLIENT_APP_NAME], status="blocked", timeout=900),
    #     )

    # Relate the charms and wait for them exchanging some connection data.
    global client_relation
    client_relation = await ops_test.model.add_relation(
        f"{OPENSEARCH_APP_NAME}:{ClientRelationName}", f"{CLIENT_APP_NAME}:first-database"
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, CLIENT_APP_NAME)

    async with ops_test.fast_forward():
        # This test shouldn't take so long
        await ops_test.model.wait_for_idle(timeout=1200, status="active")


@pytest.mark.client_relation
async def test_database_usage(ops_test: OpsTest):
    """Check we can update and delete things."""
    payload = '{"artist": "Vulfpeck", "genre": ["Funk","Jazz"], "year": 2015, "tracklist": ["Welcome to Vulf Records", "Back Pocket", "Funky Duck", "Rango II", "Game Winner", "Walkies", "Christmas in L.A.", "Conscious Club (Instrumental)", "Smile Meditation", "Guided Smile Meditation"], "title": "Thrill of the Arts"}'
    create_index_endpoint = "/albums/_doc/1"
    run_create_index = await run_request_on_application_charm(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="PUT",
        endpoint=create_index_endpoint,
        payload=payload,
        relation_id=client_relation.id,
        relation_name=FIRST_DATABASE_RELATION_NAME,
    )
    logging.error(json.dumps(run_create_index))

    read_index_endpoint = "/albums/_search?q=Jazz"
    run_read_index = await run_request_on_application_charm(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="GET",
        endpoint=read_index_endpoint,
        relation_id=client_relation.id,
        relation_name=FIRST_DATABASE_RELATION_NAME,
    )
    results = json.loads(run_read_index["results"])[0]
    logging.error(results)
    assert results.get("timed_out") is False
    assert results.get("_shards", {}).get("successful") == NUM_UNITS
    assert results.get("_shards", {}).get("failed") == 0
    assert results.get("_shards", {}).get("skipped") == 0
    assert results.get("hits", {}).get("total", {}).get("value") == 1


@pytest.mark.client_relation
async def test_database_bulk_usage(ops_test: OpsTest):
    """Check we can update and delete things using bulk api."""
    bulk_index_endpoint = "/_bulk"
    with open("tests/integration/relations/opensearch_provider/bulk_data.json") as bulk_data:
        logger.error(bulk_data)
        bulk_payload = bulk_data.read()
    logger.error(bulk_payload)
    run_bulk_create_index = await run_request_on_application_charm(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="PUT",
        endpoint=bulk_index_endpoint,
        payload=bulk_payload,
        relation_id=client_relation.id,
        relation_name=FIRST_DATABASE_RELATION_NAME,
    )
    # change assertion to "data written" or something
    logging.info(json.dumps(run_bulk_create_index["results"]))

    read_index_endpoint = "/albums/_search?q=vulfpeck"
    run_bulk_read_index = await run_request_on_application_charm(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="GET",
        endpoint=read_index_endpoint,
        relation_id=client_relation.id,
        relation_name=FIRST_DATABASE_RELATION_NAME,
    )
    # TODO assert we're getting the correct value
    results = json.dumps(run_bulk_read_index["results"])[0]
    logging.error(results)
    assert results.get("timed_out") is False
    assert results.get("_shards", {}).get("successful") == NUM_UNITS
    assert results.get("_shards", {}).get("failed") == 0
    assert results.get("_shards", {}).get("skipped") == 0
    assert results.get("hits", {}).get("total", {}).get("value") == 3


@pytest.mark.client_relation
async def test_database_version(ops_test: OpsTest):
    """Check version is accurate."""
    run_version_query = await run_request_on_application_charm(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="GET",
        endpoint="/",
        relation_id=client_relation.id,
        relation_name=FIRST_DATABASE_RELATION_NAME,
    )
    # Get the version of the database and compare with the information that
    # was retrieved directly from the database.
    version = await get_application_relation_data(
        ops_test, CLIENT_APP_NAME, FIRST_DATABASE_RELATION_NAME, "version"
    )
    logging.error(run_version_query)
    assert version in run_version_query["results"]


@pytest.mark.client_relation
async def test_multiple_relations(ops_test: OpsTest, application_charm):
    """Test that two different applications can connect to the database."""
    # Deploy secondary application.
    await ops_test.model.deploy(
        application_charm,
        application_name=SECONDARY_CLIENT_APP_NAME,
    )

    async with ops_test.fast_forward():
        await asyncio.gather(
            ops_test.model.wait_for_idle(status="active", apps=ALL_APPS),
            ops_test.model.wait_for_idle(status="blocked", apps=[SECONDARY_CLIENT_APP_NAME]),
        )

    # Relate the new application with the database
    # and wait for them exchanging some connection data.
    await ops_test.model.add_relation(
        f"{SECONDARY_CLIENT_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}", OPENSEARCH_APP_NAME
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, SECONDARY_CLIENT_APP_NAME)

    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            status="active", apps=[SECONDARY_CLIENT_APP_NAME] + ALL_APPS
        )


# @pytest.mark.smoke
# @pytest.mark.client_relation
# async def test_scaling(ops_test: OpsTest):
#     """Check these relations all work when scaling pgbouncer."""
#     await scale_application(ops_test, OPENSEARCH_APP_NAME, 5)
#     async with ops_test.fast_forward():
#         await ops_test.model.wait_for_idle(apps=ALL_APPS)

#     await scale_application(ops_test, OPENSEARCH_APP_NAME, 3)
#     async with ops_test.fast_forward():
#         await ops_test.model.wait_for_idle(apps=ALL_APPS)


@pytest.mark.client_relation
async def test_relation_broken(ops_test: OpsTest):
    """Test that the user is removed when the relation is broken."""
    async with ops_test.fast_forward():
        # Retrieve the relation user.
        relation_user = await get_application_relation_data(
            ops_test, CLIENT_APP_NAME, FIRST_DATABASE_RELATION_NAME, "username"
        )

        # Break the relation.
        await ops_test.model.applications[OPENSEARCH_APP_NAME].remove_relation(
            f"{OPENSEARCH_APP_NAME}:{ClientRelationName}",
            f"{CLIENT_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}",
        )
        await ops_test.model.wait_for_idle(
            apps=[OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME],
            status="active",
            raise_on_blocked=True,
        )
        logger.error(relation_user)

        # TODO Check that the relation user and role were both removed from the database.
        # use admin permissions from peer relation
        # write an overall test helper to run API requests using admin perms
