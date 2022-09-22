# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
from typing import Dict

from ops.charm import CharmBase

from charms.opensearch.v0.helpers.charms import Scope, SecretStore
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_tls import CertType, TLS_RELATION
from charms.tls_certificates_interface.v1.tls_certificates import TLSCertificatesRequiresV1

PEER = "opensearch-peers"


class OpenSearchBaseCharm(CharmBase):

    def __init__(self, *args):
        super().__init__(*args)

        self.opensearch: OpenSearchDistribution

        self.secrets = SecretStore(self)
        self.certs = TLSCertificatesRequiresV1(self, TLS_RELATION)

    def on_tls_conf_set(self, scope: Scope, cert_type: CertType, secret_key_prefix: str, renewal: bool):
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
