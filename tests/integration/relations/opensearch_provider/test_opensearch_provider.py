#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging
import re

import pytest
from charms.opensearch.v0.constants_charm import ClientRelationName
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import APP_NAME as OPENSEARCH_APP_NAME
from tests.integration.helpers import (
    MODEL_CONFIG,
    SERIES,
    UNIT_IDS,
    get_leader_unit_ip,
    http_request,
)
from tests.integration.relations.opensearch_provider.helpers import (
    get_application_relation_data,
    run_request,
    wait_for_relation_joined_between,
)

logger = logging.getLogger(__name__)

CLIENT_APP_NAME = "application"
SECONDARY_CLIENT_APP_NAME = "secondary-application"
TLS_CERTIFICATES_APP_NAME = "tls-certificates-operator"
ALL_APPS = [OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME, CLIENT_APP_NAME]
FIRST_DATABASE_RELATION_NAME = "first-index"

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
    await ops_test.model.relate(OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)

    global client_relation
    client_relation = await ops_test.model.add_relation(
        f"{OPENSEARCH_APP_NAME}:{ClientRelationName}", f"{CLIENT_APP_NAME}:first-index"
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, CLIENT_APP_NAME)

    async with ops_test.fast_forward():
        # This test shouldn't take so long
        await ops_test.model.wait_for_idle(timeout=1200, status="active")


@pytest.mark.client_relation
async def test_database_usage(ops_test: OpsTest):
    """Check we can update and delete things.

    The client application authenticates using the cert provided in the database; if this is
    invalid for any reason, the test will fail, so this test implicitly verifies that TLS works.
    """
    await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        relation_id=client_relation.id,
        method="PUT",
        endpoint="/albums/_doc/1",
        payload=re.escape(
            '{"artist": "Vulfpeck", "genre": ["Funk", "Jazz"], "title": "Thrill of the Arts"}'
        ),
    )

    read_index_endpoint = "/albums/_search?q=Jazz"
    run_read_index = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        endpoint=read_index_endpoint,
        method="GET",
        relation_id=client_relation.id,
    )
    results = json.loads(run_read_index["results"])
    logging.info(results)
    assert results.get("timed_out") is False
    assert results.get("hits", {}).get("total", {}).get("value") == 1
    assert (
        results.get("hits", {}).get("hits", [{}])[0].get("_source", {}).get("artist") == "Vulfpeck"
    )


@pytest.mark.client_relation
async def test_database_bulk_usage(ops_test: OpsTest):
    """Check we can update and delete things using bulk api."""
    bulk_payload = """{ "index" : { "_index": "albums", "_id" : "2" } }
{"artist": "Herbie Hancock", "genre": ["Jazz"],  "title": "Head Hunters"}
{ "index" : { "_index": "albums", "_id" : "3" } }
{"artist": "Lydian Collective", "genre": ["Jazz"],  "title": "Adventure"}
{ "index" : { "_index": "albums", "_id" : "4" } }
{"artist": "Liquid Tension Experiment", "genre": ["Prog", "Metal"],  "title": "Liquid Tension Experiment 2"}
"""
    await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        relation_id=client_relation.id,
        method="POST",
        endpoint="/_bulk",
        payload=re.escape(bulk_payload),
    )

    read_index_endpoint = "/albums/_search?q=Jazz"
    run_bulk_read_index = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        endpoint=read_index_endpoint,
        method="GET",
        relation_id=client_relation.id,
    )
    # TODO assert we're getting the correct value
    results = json.loads(run_bulk_read_index["results"])
    logging.info(results)
    assert results.get("timed_out") is False
    assert results.get("hits", {}).get("total", {}).get("value") == 3
    artists = [
        hit.get("_source", {}).get("artist") for hit in results.get("hits", {}).get("hits", [{}])
    ]
    assert set(artists) == {"Herbie Hancock", "Lydian Collective", "Vulfpeck"}


@pytest.mark.client_relation
async def test_database_version(ops_test: OpsTest):
    """Check version is accurate."""
    run_version_query = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="GET",
        endpoint="/",
        relation_id=client_relation.id,
    )
    # Get the version of the database and compare with the information that
    # was retrieved directly from the database.
    version = await get_application_relation_data(
        ops_test, f"{CLIENT_APP_NAME}/0", FIRST_DATABASE_RELATION_NAME, "version"
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


@pytest.mark.client_relation
async def test_relation_broken(ops_test: OpsTest):
    """Test that the user is removed when the relation is broken."""
    async with ops_test.fast_forward():
        # Retrieve the relation user.
        relation_user = await get_application_relation_data(
            ops_test, f"{CLIENT_APP_NAME}/0", FIRST_DATABASE_RELATION_NAME, "username"
        )

    # Break the relation.
    await ops_test.model.applications[OPENSEARCH_APP_NAME].remove_relation(
        f"{OPENSEARCH_APP_NAME}:{ClientRelationName}",
        f"{CLIENT_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}",
    )
    async with ops_test.fast_forward():
        await asyncio.gather(
            ops_test.model.wait_for_idle(
                apps=[CLIENT_APP_NAME],
                status="blocked",
            ),
            ops_test.model.wait_for_idle(
                apps=[OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME, SECONDARY_CLIENT_APP_NAME],
                status="active",
                raise_on_blocked=True,
            ),
        )
    leader_ip = await get_leader_unit_ip(ops_test)
    users = await http_request(
        ops_test,
        "GET",
        f"https://{leader_ip}:9200/_plugins/_security/api/internalusers/",
        verify=False,
    )
    logger.error(relation_user)
    logger.error(users)
    assert relation_user not in users.keys()
