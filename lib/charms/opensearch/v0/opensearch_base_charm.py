# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Operators."""
import logging
from typing import Dict, Type

from charms.opensearch.v0.helpers.databag import Scope, SecretStore
from charms.opensearch.v0.helpers.networking import get_host_ip
from charms.opensearch.v0.opensearch_config import OpenSearchConfig
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_tls import OpenSearchTLS
from charms.opensearch.v0.tls_constants import TLS_RELATION, CertType
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
)
from ops.charm import CharmBase

# The unique Charmhub library identifier, never change it
LIBID = "f4bd9c1dad554f9ea52954b8181cdc19"
LIBAPI = 0
LIBPATCH = 0


PEER = "opensearch-peers"


logger = logging.getLogger(__name__)


class OpenSearchBaseCharm(CharmBase):
    """Base class for OpenSearch charms."""

    def __init__(self, *args, distro: Type[OpenSearchDistribution] = None):
        super().__init__(*args)

        if distro is None:
            raise ValueError("The type of the opensearch distro must be specified.")

        self.opensearch = distro(self, PEER)
        self.opensearch_config = OpenSearchConfig(self.opensearch)
        self.secrets = SecretStore(self)
        self.tls = OpenSearchTLS(self, TLS_RELATION)

    def on_tls_conf_set(
        self, event: CertificateAvailableEvent, scope: Scope, cert_type: CertType, renewal: bool
    ) -> None:
        """Called after certificate ready and stored on the corresponding scope databag."""
        pass

    def on_tls_conf_remove(self):
        """Called after certificates removed."""
        pass

    @property
    def app_peers_data(self) -> Dict[str, str]:
        """Peer relation data object."""
        return self._get_relation_data(Scope.APP, PEER)

    @property
    def unit_peers_data(self) -> Dict[str, str]:
        """Peer relation data object."""
        return self._get_relation_data(Scope.UNIT, PEER)

    @property
    def unit_ip(self) -> str:
        """IP address of the current unit."""
        return get_host_ip(self, PEER)

    @property
    def unit_name(self) -> str:
        """Name of the current unit."""
        return self.unit.name.replace("/", "-")

    def _get_relation_data(self, scope: Scope, relation_name: str) -> Dict[str, str]:
        """Relation data object."""
        relation = self.model.get_relation(relation_name)
        if relation is None:
            return {}

        relation_scope = self.app if scope == Scope.APP else self.unit

        return relation.data[relation_scope]
