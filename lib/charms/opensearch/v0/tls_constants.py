# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this file we declare the constants and enums used by TLS related components."""
from charms.opensearch.v0.helpers.enums import BaseStrEnum


# The unique Charmhub library identifier, never change it
LIBID = "f4bd9c1dad554f9ea52954b8181cdc19"
LIBAPI = 0
LIBPATCH = 0


TLS_RELATION = "certificates"


class CertType(BaseStrEnum):
    """Certificate types."""

    APP_ADMIN = "app-admin"  # admin / management of cluster
    # APP_CLIENT_HTTP = "app-client-http"  # external http clients (rest layer)
    UNIT_TRANSPORT = "unit-transport"  # internal node to node communication (transport layer)
    UNIT_HTTP = "unit-http"  # http for nodes (rest layer) - units act as servers


class TlsFileExt(BaseStrEnum):
    """Extensions of TLS generated files."""

    CA = ".ca"
    CERT = ".cert"
    CHAIN = ".chain"
    CSR = ".csr"
    KEY = ".key"
    KEYPASS = ".key-password"
