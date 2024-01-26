#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..ha.helpers import SECOND_APP_NAME, assert_continuous_writes_consistency
from ..helpers import (
    APP_NAME,
    MODEL_CONFIG,
    SERIES,
    app_name,
    get_application_unit_ids,
    get_leader_unit_ip,
)
from ..helpers_deployments import wait_until
from ..tls.helpers import TLS_CERTIFICATES_APP_NAME
from .helpers_data import delete_index, index_doc, search
from .test_horizontal_scaling import IDLE_PERIOD

logger = logging.getLogger(__name__)


@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, self_signed_operator) -> None:
    """Build and deploy one unit of OpenSearch."""
    # it is possible for users to provide their own cluster for HA testing.
    # Hence, check if there is a pre-existing cluster.
    if await app_name(ops_test):
        return

    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    await asyncio.gather(
        ops_test.model.deploy(my_charm, num_units=2, series=SERIES),
    )

    # Relate it to OpenSearch to set up TLS.
    tls = await self_signed_operator
    await ops_test.model.relate(APP_NAME, tls)
    await ops_test.model.wait_for_idle(
        apps=[tls, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 2


# put this test at the end of the list of tests, as we delete an app during cleanup
# and the safeguards we have on the charm prevent us from doing so, so we'll keep
# using a unit without need - when other tests may need the unit on the CI
@pytest.mark.group(1)
async def test_multi_clusters_db_isolation(
    ops_test: OpsTest,
    c_writes,
) -> None:
    """Check that writes in cluster not replicated to another cluster."""
    app = (await app_name(ops_test)) or APP_NAME

    # remove 1 unit (for CI)
    unit_ids = get_application_unit_ids(ops_test, app=app)

    # deploy new cluster
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(my_charm, num_units=1, application_name=SECOND_APP_NAME)
    await ops_test.model.relate(SECOND_APP_NAME, TLS_CERTIFICATES_APP_NAME)

    # wait
    await wait_until(
        ops_test,
        apps=[app, SECOND_APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={app: len(unit_ids), SECOND_APP_NAME: 1},
        idle_period=IDLE_PERIOD,
        timeout=1600,
    )

    index_name = "test_index_unique_cluster_dbs"

    # index document in the current cluster
    main_app_leader_unit_ip = await get_leader_unit_ip(ops_test, app=app)
    await index_doc(ops_test, app, main_app_leader_unit_ip, index_name, doc_id=1)

    # index document in second cluster
    second_app_leader_ip = await get_leader_unit_ip(ops_test, app=SECOND_APP_NAME)
    await index_doc(ops_test, SECOND_APP_NAME, second_app_leader_ip, index_name, doc_id=2)

    # fetch all documents in each cluster
    current_app_docs = await search(ops_test, app, main_app_leader_unit_ip, index_name)
    second_app_docs = await search(ops_test, SECOND_APP_NAME, second_app_leader_ip, index_name)

    # check that the only doc indexed in each cluster is different
    assert len(current_app_docs) == 1
    assert len(second_app_docs) == 1
    assert current_app_docs[0] != second_app_docs[0]

    # cleanup
    await delete_index(ops_test, app, main_app_leader_unit_ip, index_name)
    await ops_test.model.remove_application(SECOND_APP_NAME)

    # continuous writes checks
    await assert_continuous_writes_consistency(ops_test, c_writes, app)
