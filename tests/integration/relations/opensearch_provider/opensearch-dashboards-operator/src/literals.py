#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of global literals for the charm."""

OPENSEARCH_DASHBOARDS_SNAP_REVISION = "8"

SUBSTRATE = "vm"
CHARM_KEY = "opensearch-dashboards"

PEER = "dashboard_peers"
OPENSEARCH_REL_NAME = "opensearch_client"
DASHBOARD_INDEX = ".opensearch-dashboards"
CONTAINER = "opensearch-dashboards"
CHARM_USERS = ["monitor"]
CERTS_REL_NAME = "certificates"
SERVER_PORT = 5601

PATHS = {
    "CONF": "/var/snap/opensearch-dashboards/current/etc/opensearch-dashboards",
    "DATA": "/var/snap/opensearch-dashboards/common/var/lib/opensearch-dashboards",
    "LOGS": "/var/snap/opensearch-dashboards/common/var/log/opensearch-dashboards",
    "BIN": "/snap/opensearch-dashboards/current/opt/opensearch-dashboards",
}

PEER_APP_SECRETS = [
    "admin-username",
    "admin-password",
    "kibanaserver-username",
    "kibanaserver-password",
]
PEER_UNIT_SECRETS = ["ca-cert", "csr", "certificate", "private-key"]

RESTART_TIMEOUT = 30
