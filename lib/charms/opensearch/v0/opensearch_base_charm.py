# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Operators."""

from abc import ABC
from typing import Dict

from charms.opensearch.v0.helpers.databag import Scope, SecretStore
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_tls import TLS_RELATION, CertType
from charms.tls_certificates_interface.v1.tls_certificates import (
    TLSCertificatesRequiresV1,
)
from ops.charm import CharmBase

PEER = "opensearch-peers"


class OpenSearchBaseCharm(ABC, CharmBase):
    """Base class for OpenSearch charms."""

    def __init__(self, *args):
        super().__init__(*args)

        self.opensearch: OpenSearchDistribution

        self.secrets = SecretStore(self)
        self.certs = TLSCertificatesRequiresV1(self, TLS_RELATION)

    def on_tls_conf_set(
        self, scope: Scope, cert_type: CertType, secret_key_prefix: str, renewal: bool
    ) -> None:
        """Called after certificate ready and stored on the corresponding scope databag."""
        pass

    def on_tls_conf_remove(self):
        """Called after certificates removed."""
        pass

    @property
    def app_peers_data(self) -> Dict[str, str]:
        """Peer relation data object."""
        relation = self.model.get_relation(PEER)
        if relation is None:
            return {}

        return relation.data[self.app]

    @property
    def unit_peers_data(self) -> Dict[str, str]:
        """Peer relation data object."""
        relation = self.model.get_relation(PEER)
        if relation is None:
            return {}

        return relation.data[self.unit]
