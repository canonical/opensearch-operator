#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import socket
import subprocess

import pytest
import yaml
from pytest_operator.plugin import OpsTest

from ..helpers import (
    APP_NAME,
    CONFIG_OPTS,
    IDLE_PERIOD,
    MODEL_CONFIG,
    SERIES,
    get_application_unit_ids,
)
from ..helpers_deployments import wait_until
from ..tls.test_tls import TLS_CERTIFICATES_APP_NAME

logger = logging.getLogger(__name__)


DEFAULT_NUM_UNITS = 3


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test: OpsTest, lxd_spaces) -> None:
    """Build and deploy OpenSearch.

    For this test, we will misconfigure space bindings and see if the charm still
    respects the setup.

    More information: gh:canonical/opensearch-operator#334
    """
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.set_config(MODEL_CONFIG)

    # Create a deployment that binds to the wrong space.
    # That should trigger #334.
    await ops_test.model.deploy(
        my_charm,
        num_units=DEFAULT_NUM_UNITS,
        series=SERIES,
        constraints="spaces=alpha,client,cluster,backup",
        bind={"": "cluster"},
        config=CONFIG_OPTS,
    )
    config = {"ca-common-name": "CN_CA"}
    await ops_test.model.deploy(
        TLS_CERTIFICATES_APP_NAME,
        channel="stable",
        constraints="spaces=alpha,client,cluster,backup",
        bind={"": "cluster"},
        config=config,
    )
    # Relate it to OpenSearch to set up TLS.
    await ops_test.model.integrate(APP_NAME, TLS_CERTIFICATES_APP_NAME)
    await wait_until(
        ops_test,
        apps=[APP_NAME],
        apps_statuses=["active"],
        units_statuses=["active"],
        wait_for_exact_units=DEFAULT_NUM_UNITS,
        timeout=1400,
        idle_period=IDLE_PERIOD,
    )
    assert len(ops_test.model.applications[APP_NAME].units) == DEFAULT_NUM_UNITS


@pytest.mark.runner(["self-hosted", "linux", "X64", "jammy", "large"])
@pytest.mark.group(1)
@pytest.mark.abort_on_fail
async def test_check_opensearch_transport(ops_test: OpsTest) -> None:
    """Test which IP will be assigned to transport bind in the end."""
    ids = get_application_unit_ids(ops_test, APP_NAME)
    # Build the dict containing each id - opensearch-peers' ingress IP
    ids_to_addr = {}
    for id in ids:
        ids_to_addr[id] = yaml.safe_load(
            subprocess.check_output(
                f"juju exec --unit opensearch/{id} -- network-get opensearch-peers".split()
            ).decode()
        )["bind-addresses"][0]["addresses"][0]["address"]

    logger.info(f"IPs assigned to opensearch-peers: {ids_to_addr}")

    # Now, for each unit, we must ensure all opensearch-peers' ingress IPs are present
    for id in ids_to_addr.keys():
        hosts = (
            subprocess.check_output(
                f"juju ssh opensearch/{id} -- sudo cat /var/snap/opensearch/current/etc/opensearch/unicast_hosts.txt".split()
            )
            .decode()
            .rsplit()
        )
        addrs = list(ids_to_addr.values())
        assert sorted(addrs) == sorted(hosts), f"Expected {sorted(addrs)}, got {sorted(hosts)}"

        # Now, ensure we only have IPs
        for host in hosts:
            # It will throw a socket.error exception otherwise
            assert socket.inet_aton(host)
