# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Operators."""
import logging
from typing import Dict, Type

from charms.opensearch.v0.helpers.databag import Scope, SecretStore
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_tls import OpenSearchTLS
from charms.opensearch.v0.tls_constants import TLS_RELATION, CertType
from ops.charm import CharmBase

# The unique Charmhub library identifier, never change it
LIBID = "f4bd9c1dad554f9ea52954b8181cdc19"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


PEER = "opensearch-peers"


logger = logging.getLogger(__name__)


class OpenSearchBaseCharm(CharmBase):
    """Base class for OpenSearch charms."""

    def __init__(self, *args, distro: Type[OpenSearchDistribution] = None):
        super().__init__(*args)

        if distro is None:
            raise ValueError("The type of the opensearch distro must be specified.")

        self.opensearch = distro(self, PEER)
        self.secrets = SecretStore(self)
        self.tls = OpenSearchTLS(self, TLS_RELATION)

    def on_tls_conf_set(self, scope: Scope, cert_type: CertType, renewal: bool) -> None:
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

    def _get_relation_data(self, scope: Scope, relation_name: str) -> Dict[str, str]:
        """Relation data object."""
        relation = self.model.get_relation(relation_name)
        if relation is None:
            return {}

        relation_scope = self.app if scope == Scope.APP else self.unit

        return relation.data[relation_scope]
