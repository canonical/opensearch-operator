# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.


import asyncio
import logging

import pytest
from pytest_operator.plugin import OpsTest

from ..helpers import (
    APP_NAME,
    CONFIG_OPTS,
    MODEL_CONFIG,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME, TLS_STABLE_CHANNEL

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, charm, series) -> None:
    """Build and deploy one unit of OpenSearch."""
    await ops_test.model.set_config(MODEL_CONFIG)
    # Deploy TLS Certificates operator.
    config = {"ca-common-name": "CN_CA"}
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_CERTIFICATES_APP_NAME, channel=TLS_STABLE_CHANNEL, config=config
        ),
        ops_test.model.deploy(
            charm, num_units=1, series=series, config=CONFIG_OPTS, constraints="mem=4G"
        ),
    )

    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)


@pytest.mark.abort_on_fail
async def test_wait_blocked_cluster_topology(ops_test: OpsTest) -> None:
    """Wait for blocked cluster with cluster topology error"""
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_full_statuses={
            APP_NAME: {
                "blocked": [
                    "At least 3 cluster manager nodes are required. Found only 1. - At least 3 data nodes are required. Found only 1."
                ]
            }
        },
        units_full_statuses={
            APP_NAME: {
                "units": {
                    "blocked": [
                        "At least 3 cluster manager nodes are required. Found only 1. - At least 3 data nodes are required. Found only 1."
                    ]
                }
            }
        },
    )


@pytest.mark.abort_on_fail
async def test_scale_to_active(ops_test: OpsTest) -> None:
    """Scale the OpenSearch cluster to the active state."""
    os_app = ops_test.model.applications[APP_NAME]
    await os_app.add_units(count=2)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
    )


@pytest.mark.abort_on_fail
async def test_clean_cluster_topology(ops_test: OpsTest) -> None:
    """Clean the cluster topology error scenario."""
    # Remove the cluster topology error by scaling the cluster.
    await ops_test.model.remove_application(APP_NAME, block_until_done=True)


@pytest.mark.abort_on_fail
async def test_insufficient_memory(ops_test: OpsTest, charm: str, series: str) -> None:
    """Test insufficient memory scenario."""
    await ops_test.model.deploy(
        charm, num_units=3, series=series, config=CONFIG_OPTS, constraints="mem=3G"
    )
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_full_statuses={APP_NAME: {"blocked": ["Insufficient memory: 3145728.0 < 4194304"]}},
        units_full_statuses={
            APP_NAME: {
                "units": {
                    "blocked": [
                        "Insufficient memory: 3145728.0 < 4194304",
                        "Requesting lock on operation: start",
                    ]
                }
            }
        },
    )
