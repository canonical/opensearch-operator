# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Operators."""
import logging
from typing import Dict, Type

from ops.framework import EventBase
from ops.model import BlockedStatus

from charms.opensearch.v0.helpers.databag import Scope, SecretStore
from charms.opensearch.v0.helpers.networking import get_host_ip
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution, OpenSearchMissingSysReqError
from charms.opensearch.v0.opensearch_tls import OpenSearchTLS
from charms.opensearch.v0.tls_constants import TLS_RELATION, CertType
from ops.charm import CharmBase

from charms.tls_certificates_interface.v1.tls_certificates import CertificateAvailableEvent

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

    def on_tls_conf_set(self, event: CertificateAvailableEvent, scope: Scope, cert_type: CertType, renewal: bool) -> None:
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

    def _deferred_because_missing_reqs(self, event: EventBase) -> bool:
        """Check if missing system requirements, if yes - defer."""
        try:
            self.opensearch.check_missing_sys_requirements()
            return False
        except OpenSearchMissingSysReqError as e:
            self.unit.status = BlockedStatus(" - ".join(e.missing_requirements))
            event.defer()
            return True
