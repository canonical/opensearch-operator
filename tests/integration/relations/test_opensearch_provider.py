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

from ..helpers import APP_NAME as OPENSEARCH_APP_NAME
from ..helpers import (
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids,
    get_leader_unit_ip,
    http_request,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME
from .helpers import (
    get_application_relation_data,
    ip_to_url,
    run_request,
    wait_for_relation_joined_between,
)

logger = logging.getLogger(__name__)

CLIENT_APP_NAME = "application"
SECONDARY_CLIENT_APP_NAME = "secondary-application"
ALL_APPS = [OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME, CLIENT_APP_NAME]

NUM_UNITS = 3

FIRST_RELATION_NAME = "first-index"
SECOND_RELATION_NAME = "second-index"
ADMIN_RELATION_NAME = "admin"
PROTECTED_INDICES = [
    ".opendistro_security",
    ".opendistro-alerting-config",
    ".opendistro-alerting-alert",
    ".opendistro-anomaly-results",
    ".opendistro-anomaly-detector",
    ".opendistro-anomaly-checkpoints",
    ".opendistro-anomaly-detection-state",
]


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_create_relation(ops_test: OpsTest, application_charm, opensearch_charm):
    """Test basic functionality of relation interface."""
    # Deploy both charms (multiple units for each application to test that later they correctly
    # set data in the relation application databag using only the leader unit).
    new_model_conf = MODEL_CONFIG.copy()
    new_model_conf["update-status-hook-interval"] = "1m"

    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(TLS_CERTIFICATES_APP_NAME, channel="stable", config=config)

    await ops_test.model.set_config(new_model_conf)
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
    )
    await ops_test.model.integrate(OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME)

    global client_relation
    client_relation = await ops_test.model.integrate(
        f"{OPENSEARCH_APP_NAME}:{ClientRelationName}", f"{CLIENT_APP_NAME}:{FIRST_RELATION_NAME}"
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, CLIENT_APP_NAME)

    # This test shouldn't take so long
    await ops_test.model.wait_for_idle(
        apps=ALL_APPS,
        timeout=1600,
        status="active",
    )


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
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
        endpoint="/albums/_doc/1?refresh=true",
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


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
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
        endpoint="/_bulk?refresh=true",
        payload=re.escape(bulk_payload),
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
    # TODO assert we're getting the correct value
    results = json.loads(run_bulk_read_index["results"])
    logging.info(results)
    assert results.get("timed_out") is False
    assert results.get("hits", {}).get("total", {}).get("value") == 3
    artists = [
        hit.get("_source", {}).get("artist") for hit in results.get("hits", {}).get("hits", [{}])
    ]
    assert set(artists) == {"Herbie Hancock", "Lydian Collective", "Vulfpeck"}


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
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
    assert version == results.get("version", {}).get("number"), results


async def get_secret_data(ops_test, secret_uri):
    secret_unique_id = secret_uri.split("/")[-1]
    complete_command = f"show-secret {secret_uri} --reveal --format=json"
    _, stdout, _ = await ops_test.juju(*complete_command.split())
    return json.loads(stdout)[secret_unique_id]["content"]["Data"]


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_scaling(ops_test: OpsTest):
    """Test that scaling correctly updates endpoints in databag.

    scale_application also contains a wait_for_idle check, including checking for active status.
    Idle_period checks must be greater than 1 minute to guarantee update_status fires correctly.
    """

    async def rel_endpoints(app_name: str, rel_name: str) -> str:
        return await get_application_relation_data(
            ops_test, f"{app_name}/0", rel_name, "endpoints"
        )

    async def _is_number_of_endpoints_valid(client_app: str, rel: str) -> bool:
        units = get_application_unit_ids(ops_test, OPENSEARCH_APP_NAME)
        endpoints = await rel_endpoints(client_app, rel)
        return len(units) == len(endpoints.split(","))

    # Test things are already working fine
    assert await _is_number_of_endpoints_valid(
        CLIENT_APP_NAME, FIRST_RELATION_NAME
    ), await rel_endpoints(CLIENT_APP_NAME, FIRST_RELATION_NAME)
    await wait_until(
        ops_test,
        apps=ALL_APPS,
        apps_statuses=["active"],
        idle_period=70,
    )

    # Test scale down
    opensearch_unit_ids = get_application_unit_ids(ops_test, OPENSEARCH_APP_NAME)
    await ops_test.model.applications[OPENSEARCH_APP_NAME].destroy_unit(
        f"{OPENSEARCH_APP_NAME}/{max(opensearch_unit_ids)}"
    )
    await wait_until(
        ops_test,
        apps=ALL_APPS,
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={OPENSEARCH_APP_NAME: len(opensearch_unit_ids) - 1},
        idle_period=70,
    )
    assert await _is_number_of_endpoints_valid(
        CLIENT_APP_NAME, FIRST_RELATION_NAME
    ), await rel_endpoints(CLIENT_APP_NAME, FIRST_RELATION_NAME)

    # test scale back up again
    await ops_test.model.applications[OPENSEARCH_APP_NAME].add_unit(count=1)
    await wait_until(
        ops_test,
        apps=ALL_APPS,
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={OPENSEARCH_APP_NAME: len(opensearch_unit_ids)},
        idle_period=50,  # slightly less than update-status-interval period
    )
    # Now, we want to sleep until an update-status happens
    time.sleep(30)
    assert await _is_number_of_endpoints_valid(
        CLIENT_APP_NAME, FIRST_RELATION_NAME
    ), await rel_endpoints(CLIENT_APP_NAME, FIRST_RELATION_NAME)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_multiple_relations(ops_test: OpsTest, application_charm):
    """Test that two different applications can connect to the database."""
    # scale-down for CI
    logger.info("Removing 1 unit for CI and sleep a minute..")
    opensearch_unit_ids = get_application_unit_ids(ops_test, app=OPENSEARCH_APP_NAME)
    await ops_test.model.applications[OPENSEARCH_APP_NAME].destroy_unit(
        f"{OPENSEARCH_APP_NAME}/{max(opensearch_unit_ids)}"
    )

    # sleep a minute to ease the load on machine
    time.sleep(60)

    # Deploy secondary application.
    logger.info(f"Deploying 1 unit of {SECONDARY_CLIENT_APP_NAME}")
    await ops_test.model.deploy(
        application_charm,
        num_units=1,
        application_name=SECONDARY_CLIENT_APP_NAME,
    )

    # Relate the new application and wait for them to exchange connection data.
    logger.info(
        f"Adding relation {SECONDARY_CLIENT_APP_NAME}:{SECOND_RELATION_NAME} with {OPENSEARCH_APP_NAME}"
    )
    second_client_relation = await ops_test.model.integrate(
        f"{SECONDARY_CLIENT_APP_NAME}:{SECOND_RELATION_NAME}", OPENSEARCH_APP_NAME
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, SECONDARY_CLIENT_APP_NAME)

    await wait_until(
        ops_test,
        apps=ALL_APPS + [SECONDARY_CLIENT_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={
            OPENSEARCH_APP_NAME: len(opensearch_unit_ids) - 1,
            CLIENT_APP_NAME: 1,
            SECONDARY_CLIENT_APP_NAME: 1,
            TLS_CERTIFICATES_APP_NAME: 1,
        },
        idle_period=70,
        timeout=2000,
    )

    # Test that the permissions are respected between relations by running the same request as
    # before, but expecting it to fail. SECOND_RELATION_NAME doesn't contain permissions for the
    # `albums` index, so we are expecting a 403 forbidden error.
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

    results = json.loads(run_read_index["results"])
    logging.info(results)
    assert "403 Client Error: Forbidden for url:" in results[0], results


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_multiple_relations_accessing_same_index(ops_test: OpsTest):
    """Test that two different applications can connect to the database."""
    # Relate the new application and wait for them to exchange connection data.
    second_app_first_client_relation = await ops_test.model.integrate(
        f"{SECONDARY_CLIENT_APP_NAME}:{FIRST_RELATION_NAME}", OPENSEARCH_APP_NAME
    )
    await wait_until(
        ops_test,
        apps=ALL_APPS + [SECONDARY_CLIENT_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        idle_period=70,
    )

    # Test that different applications can access the same index if they present it in their
    # relation databag. FIRST_RELATION_NAME contains `albums` in its databag, so we should be able
    # to query that index if we want.
    unit = ops_test.model.applications[SECONDARY_CLIENT_APP_NAME].units[0]
    read_index_endpoint = "/albums/_search?q=Jazz"
    run_bulk_read_index = await run_request(
        ops_test,
        unit_name=unit.name,
        endpoint=read_index_endpoint,
        method="GET",
        relation_id=second_app_first_client_relation.id,
        relation_name=FIRST_RELATION_NAME,
    )
    results = json.loads(run_bulk_read_index["results"])
    logging.info(results)
    artists = [
        hit.get("_source", {}).get("artist") for hit in results.get("hits", {}).get("hits", [{}])
    ]
    assert set(artists) == {"Herbie Hancock", "Lydian Collective", "Vulfpeck"}


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_admin_relation(ops_test: OpsTest):
    """Test we can create relations with admin permissions."""
    # Add an admin relation and wait for them to exchange data
    global admin_relation
    admin_relation = await ops_test.model.integrate(
        f"{CLIENT_APP_NAME}:{ADMIN_RELATION_NAME}", OPENSEARCH_APP_NAME
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, CLIENT_APP_NAME)
    await wait_until(
        ops_test,
        apps=ALL_APPS + [SECONDARY_CLIENT_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        idle_period=70,
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


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_admin_permissions(ops_test: OpsTest):
    """Test admin permissions behave the way we want.

    admin-only actions include:
    - creating multiple indices
    - removing indices they've created
    - set cluster roles.

    verify that:
    - we can't remove .opendistro_security index
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
    results = json.loads(run_dump_users["results"])
    logging.info(results)
    assert "403 Client Error: Forbidden for url:" in results[0], results

    # verify admin can't delete users
    secret_uri = await get_application_relation_data(
        ops_test, f"{CLIENT_APP_NAME}/0", FIRST_RELATION_NAME, "secret-user"
    )

    first_relation_user_data = await get_secret_data(ops_test, secret_uri)
    first_relation_user = first_relation_user_data.get("username")

    first_relation_user_endpoint = f"/_plugins/_security/api/internalusers/{first_relation_user}"
    run_delete_users = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint=first_relation_user_endpoint,
        method="DELETE",
        relation_id=admin_relation.id,
        relation_name=ADMIN_RELATION_NAME,
    )
    results = json.loads(run_delete_users["results"])
    logging.info(results)
    assert "403 Client Error: Forbidden for url:" in results[0], results

    # verify admin can't modify protected indices
    for protected_index in PROTECTED_INDICES:
        protected_index_endpoint = f"/{protected_index}"
        run_remove_distro = await run_request(
            ops_test,
            unit_name=test_unit.name,
            endpoint=protected_index_endpoint,
            method="DELETE",
            relation_id=admin_relation.id,
            relation_name=ADMIN_RELATION_NAME,
        )
        results = json.loads(run_remove_distro["results"])
        logging.info(results)
        assert "Error:" in results[0], results


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_normal_user_permissions(ops_test: OpsTest):
    """Test normal user permissions behave the way we want.

    verify that:
    - we can't remove .opendistro_security index
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
    assert "403 Client Error: Forbidden for url:" in results[0], results

    # verify normal users can't delete users
    secret_uri = await get_application_relation_data(
        ops_test, f"{CLIENT_APP_NAME}/0", FIRST_RELATION_NAME, "secret-user"
    )
    first_relation_user_data = await get_secret_data(ops_test, secret_uri)
    first_relation_user = first_relation_user_data.get("username")

    first_relation_user_endpoint = f"/_plugins/_security/api/internalusers/{first_relation_user}"
    run_delete_users = await run_request(
        ops_test,
        unit_name=test_unit.name,
        endpoint=first_relation_user_endpoint,
        method="DELETE",
        relation_id=client_relation.id,
        relation_name=FIRST_RELATION_NAME,
    )
    results = json.loads(run_delete_users["results"])
    logging.info(results)
    assert "403 Client Error: Forbidden for url:" in results[0], results

    # verify user can't modify protected indices
    for protected_index in PROTECTED_INDICES:
        protected_index_endpoint = f"/{protected_index}"
        run_remove_index = await run_request(
            ops_test,
            unit_name=test_unit.name,
            endpoint=protected_index_endpoint,
            method="DELETE",
            relation_id=client_relation.id,
            relation_name=FIRST_RELATION_NAME,
        )
        results = json.loads(run_remove_index["results"])
        logging.info(results)
        assert "Error:" in results[0], results


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_relation_broken(ops_test: OpsTest):
    """Test that the user is removed when the relation is broken."""
    # Retrieve the relation user.
    secret_uri = await get_application_relation_data(
        ops_test, f"{CLIENT_APP_NAME}/0", FIRST_RELATION_NAME, "secret-user"
    )

    client_app_user_data = await get_secret_data(ops_test, secret_uri)
    relation_user = client_app_user_data.get("username")

    await wait_until(
        ops_test,
        apps=ALL_APPS + [SECONDARY_CLIENT_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        idle_period=70,
    )

    # Break the relation.
    await asyncio.gather(
        ops_test.model.applications[OPENSEARCH_APP_NAME].remove_relation(
            f"{OPENSEARCH_APP_NAME}:{ClientRelationName}",
            f"{CLIENT_APP_NAME}:{FIRST_RELATION_NAME}",
        ),
        ops_test.model.applications[OPENSEARCH_APP_NAME].remove_relation(
            f"{OPENSEARCH_APP_NAME}:{ClientRelationName}",
            f"{CLIENT_APP_NAME}:{ADMIN_RELATION_NAME}",
        ),
    )

    await asyncio.gather(
        wait_until(ops_test, apps=[CLIENT_APP_NAME], apps_statuses=["blocked"], idle_period=70),
        wait_until(
            ops_test,
            apps=[OPENSEARCH_APP_NAME, TLS_CERTIFICATES_APP_NAME, SECONDARY_CLIENT_APP_NAME],
            apps_statuses=["active"],
            units_statuses=["active"],
            idle_period=70,
        ),
    )

    leader_ip = await get_leader_unit_ip(ops_test)
    users = await http_request(
        ops_test,
        "GET",
        f"https://{ip_to_url(leader_ip)}:9200/_plugins/_security/api/internalusers/",
        verify=False,
    )
    logger.info(relation_user)
    logger.info(users)
    assert relation_user not in users.keys()


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_data_persists_on_relation_rejoin(ops_test: OpsTest):
    """Verify that if we recreate a relation, we can access the same index."""
    client_relation = await ops_test.model.integrate(
        f"{OPENSEARCH_APP_NAME}:{ClientRelationName}", f"{CLIENT_APP_NAME}:{FIRST_RELATION_NAME}"
    )
    wait_for_relation_joined_between(ops_test, OPENSEARCH_APP_NAME, CLIENT_APP_NAME)

    await wait_until(
        ops_test,
        apps=ALL_APPS + [SECONDARY_CLIENT_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        idle_period=70,
    ),

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
