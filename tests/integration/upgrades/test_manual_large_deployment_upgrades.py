#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging

import pytest
from charms.opensearch.v0.constants_charm import PClusterNoRelation
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..ha.helpers import (
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
)
from ..helpers import APP_NAME, MODEL_CONFIG, set_watermark
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .helpers import (
    IDLE_PERIOD,
    OPENSEARCH_CHANNEL,
    OPENSEARCH_CHARM,
    UPGRADE_PARAMS,
    VERSION_N,
    VERSION_N_MINUS_1,
    VERSION_N_MINUS_2,
    VERSION_TO_REVISION,
    assert_rollback_to_revision,
    assert_upgrade_to_local,
    assert_upgrade_to_revision,
    assert_version_units,
    testing_config_if_supported,
)

logger = logging.getLogger(__name__)

MAIN_APP = "main"
FAILOVER_APP = "failover"

REL_ORCHESTRATOR = "peer-cluster-orchestrator"
REL_PEER = "peer-cluster"
TIMEOUT = 1800

charm = None

APPS = {
    APP_NAME: 3,
    FAILOVER_APP: 2,
    MAIN_APP: 3,
}


async def _build_env(ops_test: OpsTest, version: str, series: str) -> None:
    """Sets up environment for given version and series"""
    await ops_test.model.set_config(MODEL_CONFIG)

    # Deploy TLS Certificates operator.
    tls_config = {"ca-common-name": "CN_CA"}

    revision = VERSION_TO_REVISION[version][series]
    config = testing_config_if_supported(revision)
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=tls_config
        ),
        ops_test.model.deploy(
            OPENSEARCH_CHARM,
            channel=OPENSEARCH_CHANNEL,
            application_name=MAIN_APP,
            num_units=APPS[MAIN_APP],
            revision=revision,
            series=series,
            config={"cluster_name": "upgrades"} | config,
        ),
        ops_test.model.deploy(
            OPENSEARCH_CHARM,
            channel=OPENSEARCH_CHANNEL,
            application_name=FAILOVER_APP,
            num_units=APPS[FAILOVER_APP],
            revision=revision,
            series=series,
            config={"cluster_name": "upgrades", "init_hold": True, "roles": "cluster_manager"}
            | config,
        ),
        ops_test.model.deploy(
            OPENSEARCH_CHARM,
            channel=OPENSEARCH_CHANNEL,
            application_name=APP_NAME,
            num_units=APPS[APP_NAME],
            revision=revision,
            series=series,
            config={"cluster_name": "upgrades", "init_hold": True, "roles": "data"} | config,
        ),
    )

    # integrate TLS to all applications
    for app in list(APPS.keys()):
        await ops_test.model.integrate(app, TLS_CERTIFICATES_APP_NAME)

    await wait_until(
        ops_test,
        apps=list(APPS.keys()),
        apps_full_statuses={
            MAIN_APP: {"active": []},
            FAILOVER_APP: {"blocked": [PClusterNoRelation]},
            APP_NAME: {"blocked": [PClusterNoRelation]},
        },
        units_full_statuses={
            MAIN_APP: {"units": {"active": []}},
            FAILOVER_APP: {"units": {"active": []}},
            APP_NAME: {"units": {"active": []}},
        },
        wait_for_exact_units={app: units for app, units in APPS.items()},
        idle_period=IDLE_PERIOD,
        timeout=TIMEOUT,
    )

    await ops_test.model.integrate(f"{MAIN_APP}:{REL_ORCHESTRATOR}", f"{APP_NAME}:{REL_PEER}")
    await ops_test.model.integrate(f"{MAIN_APP}:{REL_ORCHESTRATOR}", f"{FAILOVER_APP}:{REL_PEER}")
    await ops_test.model.integrate(f"{FAILOVER_APP}:{REL_ORCHESTRATOR}", f"{APP_NAME}:{REL_PEER}")

    await wait_until(
        ops_test,
        apps=list(APPS.keys()),
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units={app: units for app, units in APPS.items()},
        idle_period=IDLE_PERIOD,
        timeout=TIMEOUT,
    )

    for app in list(APPS.keys()):
        await set_watermark(ops_test, app)


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_starting_version(ops_test: OpsTest, series) -> None:
    """Build and deploy the charm for large deployment tests."""
    # deploy version n-2 for current series
    await _build_env(ops_test, VERSION_N_MINUS_2, series)


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip("Can't upgrade between earlier versions")
# TODO: re-enable after two versions available
async def test_upgrade_to_n_minus_1(
    ops_test: OpsTest, series: str, c_writes: ContinuousWrites, c_writes_runner
) -> None:
    """Test minor version upgrade from n-2 to n-1."""
    # upgrade to version n-1 revision for current series
    revision = VERSION_TO_REVISION[VERSION_N_MINUS_1][series]
    for app in list(APPS.keys()):
        await assert_version_units(ops_test, app, VERSION_N_MINUS_2)
        await assert_upgrade_to_revision(ops_test, app, revision)
        await assert_version_units(ops_test, app, VERSION_N_MINUS_1)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, [APP_NAME, MAIN_APP])


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
async def test_upgrade_to_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, charm
) -> None:
    """Test upgrade to local charm from n-1."""
    for app in [APP_NAME, FAILOVER_APP, MAIN_APP]:
        await assert_upgrade_to_local(ops_test, app=app, charm=charm)
        await assert_version_units(ops_test, app, VERSION_N)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, [APP_NAME, MAIN_APP])


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_version(ops_test: OpsTest, version, series) -> None:
    """Deploy OpenSearch at given version."""
    await _build_env(ops_test, version, series)


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
@pytest.mark.skip("Rollbacks not supported")
# TODO re-enable after rollbacks best effort support is added
async def test_upgrade_rollback_from_local(
    ops_test: OpsTest,
    version: str,
    charm: str,
    series: str,
    c_writes: ContinuousWrites,
    c_writes_runner,
) -> None:
    """Test upgrade to local and rollback to given version."""
    revision = VERSION_TO_REVISION[version][series]
    for app in [APP_NAME, FAILOVER_APP, MAIN_APP]:
        await assert_version_units(ops_test, app, version)
        await assert_rollback_to_revision(ops_test, app, charm, revision)
        await assert_version_units(ops_test, app, version)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, [APP_NAME, MAIN_APP])


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
async def test_upgrade_from_version_to_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, version, charm
) -> None:
    """Test upgrade from usptream to local charm."""
    for app in [APP_NAME, FAILOVER_APP, MAIN_APP]:
        await assert_upgrade_to_local(ops_test, app=app, charm=charm)
        await assert_version_units(ops_test, app, VERSION_N)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, [APP_NAME, MAIN_APP])
