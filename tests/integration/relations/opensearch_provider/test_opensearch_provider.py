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
from tests.integration.helpers import MODEL_CONFIG, SERIES, UNIT_IDS
from tests.integration.relations.opensearch_provider.helpers import (
    run_query_on_application_charm,
    wait_for_relation_joined_between,
)

logger = logging.getLogger(__name__)

CLIENT_APP_NAME = "application"
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
        await ops_test.model.wait_for_idle(timeout=900, status="active")


# Here be pgbouncer code


@pytest.mark.client_relation
async def test_database_usage(ops_test: OpsTest):
    """Check we can update and delete things."""
    # TODO I stole this from amazon's opensearch docs because I didn't want to write reams of test
    # data. Should I swap this to something else?
    payload = '{"director": "Burton, Tim", "genre": ["Comedy","Sci-Fi"], "year": 1996, "actor": ["Jack Nicholson","Pierce Brosnan","Sarah Jessica Parker"], "title": "Mars Attacks!"}'
    create_index_endpoint = "/domain-endpoint/movies/_doc/1"
    run_create_index = await run_query_on_application_charm(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="PUT",
        endpoint=create_index_endpoint,
        payload=payload,
        relation_id=client_relation.id,
        relation_name=FIRST_DATABASE_RELATION_NAME,
    )
    logging.error(json.loads(run_create_index))

    # TODO make bulk data assignment
    # TODO I stole this from amazon's opensearch docs because I didn't want to write reams of test
    # data. Should I swap this to something else?
    # curl -XPOST -u 'master-user:master-user-password' 'domain-endpoint/_bulk'
    # --data-binary @bulk_movies.json -H 'Content-Type: application/json'
    bulk_index_endpoint = "domain-endpoint/_bulk"
    with open("tests/integration/relations/opensearch-provider.bulk_data.json") as bulk_data:
        bulk_payload = bulk_data.read()
    run_bulk_create_index = await run_query_on_application_charm(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="PUT",
        endpoint=bulk_index_endpoint,
        payload=bulk_payload,
        relation_id=client_relation.id,
        relation_name=FIRST_DATABASE_RELATION_NAME,
    )
    # change assertion to "data written" or something
    logging.error(json.loads(run_bulk_create_index["results"]))

    #   curl -XGET -u 'master-user:master-user-password' 'domain-endpoint/movies/_search?q=mars'
    read_index_endpoint = "domain-endpoint/movies/_search?q=mars"
    run_read_index = await run_query_on_application_charm(
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

    read_index_endpoint = "domain-endpoint/movies/_search?q=rebel"
    run_bulk_read_index = await run_query_on_application_charm(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="GET",
        endpoint=read_index_endpoint,
        relation_id=client_relation.id,
        relation_name=FIRST_DATABASE_RELATION_NAME,
    )
    # TODO assert we're getting the correct value
    results = json.loads(run_bulk_read_index["results"])[0]
    logging.error(results)
    assert results.get("timed_out") is False
    assert results.get("_shards", {}).get("successful") == NUM_UNITS
    assert results.get("_shards", {}).get("failed") == 0
    assert results.get("_shards", {}).get("skipped") == 0
    assert results.get("hits", {}).get("total", {}).get("value") == 1


# @pytest.mark.client_relation
# async def test_database_version(ops_test: OpsTest):
#     """Check version is accurate."""
#     version_query = "SELECT version();"
#     run_version_query = await run_sql_on_application_charm(
#         ops_test,
#         unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
#         query=version_query,
#         dbname=APPLICATION_FIRST_DBNAME,
#         relation_id=client_relation.id,
#         relation_name=FIRST_DATABASE_RELATION_NAME,
#     )
#     # Get the version of the database and compare with the information that
#     # was retrieved directly from the database.
#     version = await get_application_relation_data(
#         ops_test, CLIENT_APP_NAME, FIRST_DATABASE_RELATION_NAME, "version"
#     )
#     assert version in json.loads(run_version_query["results"])[0][0]


# @pytest.mark.client_relation
# async def test_multiple_relations(ops_test: OpsTest, application_charm):
#     """Test that two different applications can connect to the database."""
#     all_app_names = [SECONDARY_CLIENT_APP_NAME] + APP_NAMES

#     # Deploy secondary application.
#     await ops_test.model.deploy(
#         application_charm,
#         application_name=SECONDARY_CLIENT_APP_NAME,
#         resources={"application-image": "ubuntu:latest"},
#     )
#     await ops_test.model.wait_for_idle(status="active", apps=all_app_names)

#     # Relate the new application with the database
#     # and wait for them exchanging some connection data.
#     secondary_relation = await ops_test.model.add_relation(
#         f"{SECONDARY_CLIENT_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}", PGB
#     )
#     wait_for_relation_joined_between(ops_test, PGB, SECONDARY_CLIENT_APP_NAME)
#     await ops_test.model.wait_for_idle(status="active", apps=all_app_names)

#     # Check both relations can connect
#     await check_new_relation(
#         ops_test,
#         unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
#         relation_id=client_relation.id,
#         dbname=APPLICATION_FIRST_DBNAME,
#         relation_name=FIRST_DATABASE_RELATION_NAME,
#     )
#     await check_new_relation(
#         ops_test,
#         unit_name=ops_test.model.applications[SECONDARY_CLIENT_APP_NAME].units[0].name,
#         relation_id=secondary_relation.id,
#         dbname=SECONDARY_APPLICATION_FIRST_DBNAME,
#         table_name="check_multiple_apps_connected_to_one_cluster",
#         relation_name=FIRST_DATABASE_RELATION_NAME,
#     )

#     # Assert the two application have different relation (connection) data.
#     app_connstr = await build_connection_string(
#         ops_test, CLIENT_APP_NAME, FIRST_DATABASE_RELATION_NAME
#     )
#     secondary_app_connstr = await build_connection_string(
#         ops_test, SECONDARY_CLIENT_APP_NAME, FIRST_DATABASE_RELATION_NAME
#     )

#     logger.info(app_connstr)
#     logger.info(secondary_app_connstr)
#     assert app_connstr != secondary_app_connstr


# @pytest.mark.client_relation
# async def test_an_application_can_request_multiple_databases(ops_test: OpsTest):
#     """Test that an application can request additional databases using the same interface."""
#     # Relate the charms using another relation and wait for them exchanging some connection data.
#     await ops_test.model.add_relation(f"{CLIENT_APP_NAME}:{SECOND_DATABASE_RELATION_NAME}", PGB)
#     async with ops_test.fast_forward():
#         await ops_test.model.wait_for_idle(apps=APP_NAMES, status="active")

#     # Get the connection strings to connect to both databases.
#     first_database_connection_string = await build_connection_string(
#         ops_test, CLIENT_APP_NAME, FIRST_DATABASE_RELATION_NAME
#     )
#     second_database_connection_string = await build_connection_string(
#         ops_test, CLIENT_APP_NAME, SECOND_DATABASE_RELATION_NAME
#     )

#     # Assert the two application have different relation (connection) data.
#     assert first_database_connection_string != second_database_connection_string


# @pytest.mark.smoke
# @pytest.mark.client_relation
# async def test_scaling(ops_test: OpsTest):
#     """Check these relations all work when scaling pgbouncer."""
#     await scale_application(ops_test, PGB, 1)
#     await ops_test.model.wait_for_idle(apps=APP_NAMES)
#     await check_new_relation(
#         ops_test,
#         unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
#         relation_id=client_relation.id,
#         dbname=APPLICATION_FIRST_DBNAME,
#         relation_name=FIRST_DATABASE_RELATION_NAME,
#     )

#     await scale_application(ops_test, PGB, 2)
#     await ops_test.model.wait_for_idle(apps=APP_NAMES)
#     await check_new_relation(
#         ops_test,
#         unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
#         relation_id=client_relation.id,
#         dbname=APPLICATION_FIRST_DBNAME,
#         relation_name=FIRST_DATABASE_RELATION_NAME,
#     )


# @pytest.mark.client_relation
# async def test_relation_broken(ops_test: OpsTest):
#     """Test that the user is removed when the relation is broken."""
#     async with ops_test.fast_forward():
#         # Retrieve the relation user.
#         relation_user = await get_application_relation_data(
#             ops_test, CLIENT_APP_NAME, FIRST_DATABASE_RELATION_NAME, "username"
#         )

#         # Break the relation.
#         await ops_test.model.applications[PGB].remove_relation(
#             f"{PGB}:database", f"{CLIENT_APP_NAME}:{FIRST_DATABASE_RELATION_NAME}"
#         )
#         await ops_test.model.wait_for_idle(apps=APP_NAMES, status="active", raise_on_blocked=Tru)
#         backend_rel = get_backend_relation(ops_test)
#         pg_user, pg_pass = await get_backend_user_pass(ops_test, backend_rel)

#         # Check that the relation user was removed from the database.
#         await check_database_users_existence(
#             ops_test, [], [relation_user], pg_user=pg_user, pg_user_password=pg_pass
#         )

#     # check relation data was correctly removed from config
#     pgb_unit_name = ops_test.model.applications[PGB].units[0].name
#     cfg = await get_cfg(ops_test, pgb_unit_name)
#     assert "first-database" not in cfg["databases"].keys()
#     assert "first-database_readonly" not in cfg["databases"].keys()
