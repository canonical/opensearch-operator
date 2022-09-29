# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this file we declare the constants and enums used by TLS related components."""
from enum import Enum

TLS_RELATION = "certificates"


class CertType(Enum):
    """Certificate types."""

    APP_ADMIN = "app-admin"  # admin / management of cluster
    # APP_CLIENT_HTTP = "app-client-http"  # external http clients (rest layer)
    UNIT_TRANSPORT = "unit-transport"  # internal node to node communication (transport layer)
    UNIT_HTTP = "unit-http"  # http for nodes (rest layer) - units act as servers

    def __str__(self):
        """String representation of enum value."""
        return self.value


class TlsFileExt(Enum):
    """Extensions of TLS generated files."""

    CA = ".ca"
    CERT = ".cert"
    CHAIN = ".chain"
    CSR = ".csr"
    KEY = ".key"
    KEYPASS = ".key-password"

    def __str__(self):
        """String representation of enum value."""
        return self.value
