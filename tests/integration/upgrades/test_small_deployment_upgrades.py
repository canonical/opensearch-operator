#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..ha.continuous_writes import ContinuousWrites
from ..ha.helpers import (
    app_name,
    assert_continuous_writes_consistency,
    assert_continuous_writes_increasing,
)
from ..helpers import APP_NAME, CONFIG_OPTS, MODEL_CONFIG, set_watermark
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL
from .helpers import (
    PROFILES_REVISION,
    UPGRADE_PARAMS,
    VERSION_N,
    VERSION_N_MINUS_1,
    VERSION_N_MINUS_2,
    VERSION_TO_REVISION,
    assert_rollback_to_revision,
    assert_upgrade_to_local,
    assert_upgrade_to_revision,
    assert_version_units,
)

logger = logging.getLogger(__name__)


OPENSEARCH_ORIGINAL_CHARM_NAME = "opensearch"
OPENSEARCH_CHANNEL = "2/edge"

charm = None


#######################################################################
#
#  Auxiliary functions
#
#######################################################################


async def _build_env(ops_test: OpsTest, version: str, series) -> None:
    """Deploy OpenSearch cluster from a given revision."""
    await ops_test.model.set_config(MODEL_CONFIG)

    revision = VERSION_TO_REVISION[version][series]
    await ops_test.model.deploy(
        OPENSEARCH_ORIGINAL_CHARM_NAME,
        application_name=APP_NAME,
        num_units=3,
        channel=OPENSEARCH_CHANNEL,
        revision=revision,
        series=series,
        config=CONFIG_OPTS if revision > PROFILES_REVISION else {},
    )

    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await ops_test.model.wait_for_idle(
        apps=[TLS_CERTIFICATES_APP_NAME, APP_NAME],
        status="active",
        timeout=1400,
        idle_period=30,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == 3

    await set_watermark(ops_test, APP_NAME)


#######################################################################
#
#  Tests
#
#######################################################################


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_latest_from_channel(ops_test: OpsTest, series) -> None:
    """Deploy OpenSearch."""
    await _build_env(ops_test, VERSION_N_MINUS_2, series)


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
@pytest.mark.skip("Can't upgrade between earlier versions")
async def test_upgrade_between_versions(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, series
) -> None:
    """Test upgrade from upstream to currently locally built version."""
    app = (await app_name(ops_test)) or APP_NAME
    revision = VERSION_TO_REVISION[VERSION_N_MINUS_1][series]
    await assert_version_units(ops_test, app, VERSION_N_MINUS_2)
    await assert_upgrade_to_revision(ops_test, app=app, revision=revision)
    await assert_version_units(ops_test, app, VERSION_N_MINUS_1)


@pytest.mark.group(id="happy_path_upgrade")
@pytest.mark.abort_on_fail
async def test_upgrade_to_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, charm
) -> None:
    """Test upgrade from usptream to currently locally built version."""
    app = (await app_name(ops_test)) or APP_NAME
    await assert_upgrade_to_local(ops_test, app=app, charm=charm)
    await assert_version_units(ops_test, app, VERSION_N)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])


##################################################################################
#
#  test scenarios from each version:
#    Start with each version, moving to local and then rolling back mid-upgrade
#    Once this test passes, the 2nd test will rerun the upgrade, this time to
#    its end.
#
##################################################################################


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_deploy_from_version(ops_test: OpsTest, version, series) -> None:
    """Deploy OpenSearch."""
    await _build_env(ops_test, version, series)


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
async def test_upgrade_rollback_from_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, version, charm, series
) -> None:
    """Test upgrade and rollback to each version available."""
    app = (await app_name(ops_test)) or APP_NAME
    revision = VERSION_TO_REVISION[version][series]
    await assert_version_units(ops_test, app, version)
    await assert_rollback_to_revision(
        ops_test, app=app, charm=charm, revision=revision, version=version
    )
    await assert_version_units(ops_test, app, version)


@pytest.mark.parametrize("version", UPGRADE_PARAMS)
@pytest.mark.abort_on_fail
async def test_upgrade_from_version_to_local(
    ops_test: OpsTest, c_writes: ContinuousWrites, c_writes_runner, version, charm
) -> None:
    """Test upgrade from usptream to currently locally built version."""
    app = (await app_name(ops_test)) or APP_NAME
    await assert_upgrade_to_local(ops_test, app=app, charm=charm)
    await assert_version_units(ops_test, app, VERSION_N)

    # continuous writes checks
    await assert_continuous_writes_increasing(c_writes)
    await assert_continuous_writes_consistency(ops_test, c_writes, [app])
