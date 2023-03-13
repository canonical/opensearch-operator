#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import json
import logging
import re
import time

import pytest
from charms.opensearch.v0.constants_charm import ClientRelationName
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import APP_NAME as OPENSEARCH_APP_NAME
from tests.integration.helpers import (
    MODEL_CONFIG,
    SERIES,
    get_leader_unit_ip,
    http_request,
    scale_application,
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
FIRST_RELATION_NAME = "first-index"
SECOND_RELATION_NAME = "second-index"
ADMIN_RELATION_NAME = "admin"

NUM_UNITS = 3


@pytest.mark.abort_on_fail
async def test_create_relation(ops_test: OpsTest, application_charm, opensearch_charm):
    """Test basic functionality of relation interface."""
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
        f"{OPENSEARCH_APP_NAME}:{ClientRelationName}", f"{CLIENT_APP_NAME}:{FIRST_RELATION_NAME}"
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, CLIENT_APP_NAME)

    async with ops_test.fast_forward():
        # This test shouldn't take so long
        await ops_test.model.wait_for_idle(apps=ALL_APPS, timeout=1400, status="active")


async def test_index_usage(ops_test: OpsTest):
    """Check we can update and delete things.

    The client application authenticates using the cert provided in the index; if this is
    invalid for any reason, the test will fail, so this test implicitly verifies that TLS works.
    """
    await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        relation_name=FIRST_RELATION_NAME,
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
        relation_name=FIRST_RELATION_NAME,
    )
    results = json.loads(run_read_index["results"])
    logging.info(results)
    assert results.get("timed_out") is False
    assert results.get("hits", {}).get("total", {}).get("value") == 1
    assert (
        results.get("hits", {}).get("hits", [{}])[0].get("_source", {}).get("artist") == "Vulfpeck"
    )


async def test_bulk_index_usage(ops_test: OpsTest):
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
        relation_name=FIRST_RELATION_NAME,
        relation_id=client_relation.id,
        method="POST",
        endpoint="/_bulk",
        payload=re.escape(bulk_payload),
    )

    # Wait so we aren't writing data and requesting it straight away
    time.sleep(1)

    read_index_endpoint = "/albums/_search?q=Jazz"
    run_bulk_read_index = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        endpoint=read_index_endpoint,
        method="GET",
        relation_id=client_relation.id,
        relation_name=FIRST_RELATION_NAME,
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


async def test_version(ops_test: OpsTest):
    """Check version reported in the databag is consistent with the version on the charm."""
    run_version_request = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        method="GET",
        endpoint="/",
        relation_id=client_relation.id,
        relation_name=FIRST_RELATION_NAME,
    )
    version = await get_application_relation_data(
        ops_test, f"{CLIENT_APP_NAME}/0", FIRST_RELATION_NAME, "version"
    )
    logging.info(run_version_request)
    logging.info(version)
    results = json.loads(run_version_request["results"])
    assert version == results.get("version", {}).get("number")


async def test_multiple_relations(ops_test: OpsTest, application_charm):
    """Test that two different applications can connect to the database."""
    # Deploy secondary application.
    await ops_test.model.deploy(
        application_charm,
        application_name=SECONDARY_CLIENT_APP_NAME,
    )

    # Relate the new application and wait for them to exchange connection data.
    second_client_relation = await ops_test.model.add_relation(
        f"{SECONDARY_CLIENT_APP_NAME}:{SECOND_RELATION_NAME}", OPENSEARCH_APP_NAME
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, SECONDARY_CLIENT_APP_NAME)

    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            status="active", apps=[SECONDARY_CLIENT_APP_NAME] + ALL_APPS, timeout=(60 * 20)
        )

    # Test that the permissions are respected between relations by running the same request as
    # before, but expecting it to fail.
    unit = ops_test.model.applications[SECONDARY_CLIENT_APP_NAME].units[0]
    read_index_endpoint = "/albums/_search?q=Jazz"
    run_read_index = await run_request(
        ops_test,
        unit_name=unit.name,
        endpoint=read_index_endpoint,
        method="GET",
        relation_id=second_client_relation.id,
        relation_name=SECOND_RELATION_NAME,
    )

    status = await ops_test.model.get_status()
    ip = status["applications"][SECONDARY_CLIENT_APP_NAME].units[unit.name]["address"]
    results = json.loads(run_read_index["results"])
    logging.info(results)
    assert results == [
        f"403 Client Error: Forbidden for url: https://{ip}:9200/albums/_search?q=Jazz"
    ]


async def test_admin_relation(ops_test: OpsTest):
    """Test we can create relations with admin permissions."""
    # Add an admin relation and wait for them to exchange data
    global admin_relation
    admin_relation = await ops_test.model.add_relation(
        f"{CLIENT_APP_NAME}:{ADMIN_RELATION_NAME}", OPENSEARCH_APP_NAME
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, CLIENT_APP_NAME)
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            status="active", apps=[SECONDARY_CLIENT_APP_NAME] + ALL_APPS, timeout=(60 * 20)
        )

    # Verify we can access whatever data we like as admin
    read_index_endpoint = "/albums/_search?q=Jazz"
    run_bulk_read_index = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        endpoint=read_index_endpoint,
        method="GET",
        relation_id=admin_relation.id,
        relation_name=ADMIN_RELATION_NAME,
    )
    results = json.loads(run_bulk_read_index["results"])
    logging.info(results)
    artists = [
        hit.get("_source", {}).get("artist") for hit in results.get("hits", {}).get("hits", [{}])
    ]
    assert set(artists) == {"Herbie Hancock", "Lydian Collective", "Vulfpeck"}


async def test_admin_permissions(ops_test: OpsTest):
    """Test admin permissions behave the way we want.

    admin-only actions include:
    - creating multiple indices
    - removing indices they've created
    - set cluster roles.

    verify that:
    - we can't remove .opensearch_distro index
      - otherwise create client-admin-role
    - verify neither admin nor default users can access user api
      - otherwise create client-default-role
    """
    test_unit = ops_test.model.applications[CLIENT_APP_NAME].units[0]
    # Verify admin can't access security API
    security_api_endpoint = "/_plugins/_security/api/internalusers"
    run_dump_users = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint=security_api_endpoint,
        method="GET",
        relation_id=admin_relation.id,
        relation_name=ADMIN_RELATION_NAME,
    )

    status = await ops_test.model.get_status()
    ip = status["applications"][SECONDARY_CLIENT_APP_NAME].units[test_unit.name]["address"]
    results = json.loads(run_dump_users["results"])
    logging.info(results)
    assert results == [
        f"403 Client Error: Forbidden for url: https://{ip}:9200/.opensearch_distro"
    ]

    # verify admin can't delete .opensearch_distro
    opensearch_distro_endpoint = "/.opensearch_distro"
    run_remove_distro = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint=opensearch_distro_endpoint,
        method="DELETE",
        relation_id=admin_relation.id,
        relation_name=ADMIN_RELATION_NAME,
    )
    results = json.loads(run_remove_distro["results"])
    logging.info(results)
    # TODO this isn't failing correctly - we're getting 404 instead
    assert results == [
        f"403 Client Error: Forbidden for url: https://{ip}:9200/.opensearch_distro"
    ]


async def test_normal_user_permissions(ops_test: OpsTest):
    """Test normal user permissions behave the way we want.

    verify that:
    - we can't remove .opensearch_distro index
    - verify neither admin nor default users can access user api
    """
    test_unit = ops_test.model.applications[CLIENT_APP_NAME].units[0]

    # Verify normal users can't access security API
    security_api_endpoint = "/_plugins/_security/api/internalusers"
    run_dump_users = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint=security_api_endpoint,
        method="GET",
        relation_id=client_relation.id,
        relation_name=FIRST_RELATION_NAME,
    )
    results = json.loads(run_dump_users["results"])
    logging.info(results)

    status = await ops_test.model.get_status()
    ip = status["applications"][SECONDARY_CLIENT_APP_NAME].units[test_unit.name]["address"]
    assert results == [
        f"403 Client Error: Forbidden for url: https://{ip}:9200/.opensearch_distro"
    ]

    # verify normal users can't delete .opensearch_distro
    opensearch_distro_endpoint = "/.opensearch_distro"
    run_remove_distro = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint=opensearch_distro_endpoint,
        method="DELETE",
        relation_id=client_relation.id,
        relation_name=FIRST_RELATION_NAME,
    )
    results = json.loads(run_remove_distro["results"])
    logging.info(results)
    assert results == [
        f"403 Client Error: Forbidden for url: https://{ip}:9200/.opensearch_distro"
    ]


async def test_scaling(ops_test: OpsTest):
    """Test that scaling correctly updates endpoints in databag.

    scale_application also contains a wait_for_idle check, including checking for active status.
    """

    async def rel_endpoints(app_name) -> str:
        return await get_application_relation_data(
            ops_test, f"{app_name}/0", FIRST_RELATION_NAME, "endpoints"
        )

    async def get_num_of_endpoints(app_name: str) -> int:
        return len((await rel_endpoints(app_name)).split(","))

    def get_num_of_units() -> int:
        return len(ops_test.model.applications[OPENSEARCH_APP_NAME].units)

    # Test things are already working fine
    assert await get_num_of_endpoints(CLIENT_APP_NAME) == get_num_of_units(), await rel_endpoints(
        CLIENT_APP_NAME
    )
    assert (
        await get_num_of_endpoints(SECONDARY_CLIENT_APP_NAME) == get_num_of_units()
    ), await rel_endpoints(SECONDARY_CLIENT_APP_NAME)
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            status="active", apps=[SECONDARY_CLIENT_APP_NAME] + ALL_APPS
        )

    # Test scale down
    await scale_application(ops_test, OPENSEARCH_APP_NAME, get_num_of_units() - 1)
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            status="active", apps=[SECONDARY_CLIENT_APP_NAME] + ALL_APPS
        )
    assert await get_num_of_endpoints(CLIENT_APP_NAME) == get_num_of_units(), await rel_endpoints(
        CLIENT_APP_NAME
    )
    assert (
        await get_num_of_endpoints(SECONDARY_CLIENT_APP_NAME) == get_num_of_units()
    ), await rel_endpoints(SECONDARY_CLIENT_APP_NAME)

    # test scale back up again
    await scale_application(ops_test, OPENSEARCH_APP_NAME, get_num_of_units() + 1)
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            status="active", apps=[SECONDARY_CLIENT_APP_NAME] + ALL_APPS
        )
    assert await get_num_of_endpoints(CLIENT_APP_NAME) == get_num_of_units(), await rel_endpoints(
        CLIENT_APP_NAME
    )
    assert (
        await get_num_of_endpoints(SECONDARY_CLIENT_APP_NAME) == get_num_of_units()
    ), await rel_endpoints(SECONDARY_CLIENT_APP_NAME)


async def test_relation_broken(ops_test: OpsTest):
    """Test that the user is removed when the relation is broken."""
    # Retrieve the relation user.
    relation_user = await get_application_relation_data(
        ops_test, f"{CLIENT_APP_NAME}/0", FIRST_RELATION_NAME, "username"
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            status="active", apps=[SECONDARY_CLIENT_APP_NAME] + ALL_APPS
        )

    # Break the relation.
    await ops_test.model.applications[OPENSEARCH_APP_NAME].remove_relation(
        f"{OPENSEARCH_APP_NAME}:{ClientRelationName}",
        f"{CLIENT_APP_NAME}:{FIRST_RELATION_NAME}",
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
            ),
        )

    leader_ip = await get_leader_unit_ip(ops_test)
    users = await http_request(
        ops_test,
        "GET",
        f"https://{leader_ip}:9200/_plugins/_security/api/internalusers/",
        verify=False,
    )
    logger.info(relation_user)
    logger.info(users)
    assert relation_user not in users.keys()


async def test_data_persists_on_relation_rejoin(ops_test: OpsTest):
    """Verify that if we recreate a relation, we can access the same index."""
    client_relation = await ops_test.model.add_relation(
        f"{OPENSEARCH_APP_NAME}:{ClientRelationName}", f"{CLIENT_APP_NAME}:{FIRST_RELATION_NAME}"
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, CLIENT_APP_NAME)

    async with ops_test.fast_forward():
        # This test shouldn't take so long
        await ops_test.model.wait_for_idle(
            apps=[SECONDARY_CLIENT_APP_NAME] + ALL_APPS, timeout=1200, status="active"
        )

    read_index_endpoint = "/albums/_search?q=Jazz"
    run_bulk_read_index = await run_request(
        ops_test,
        unit_name=ops_test.model.applications[CLIENT_APP_NAME].units[0].name,
        endpoint=read_index_endpoint,
        method="GET",
        relation_id=client_relation.id,
        relation_name=FIRST_RELATION_NAME,
    )
    results = json.loads(run_bulk_read_index["results"])
    logging.info(results)
    assert results.get("timed_out") is False
    assert results.get("hits", {}).get("total", {}).get("value") == 3
    artists = [
        hit.get("_source", {}).get("artist") for hit in results.get("hits", {}).get("hits", [{}])
    ]
    assert set(artists) == {"Herbie Hancock", "Lydian Collective", "Vulfpeck"}
