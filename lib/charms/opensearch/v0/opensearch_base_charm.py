# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Operators."""
import logging
import random
import re
from typing import Dict, Type

from charms.opensearch.v0.constants_charm import HorizontalScaleUpSuggest
from charms.opensearch.v0.constants_tls import TLS_RELATION, CertType
from charms.opensearch.v0.helper_databag import Scope, SecretStore
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.helper_networking import get_host_ip, units_ips
from charms.opensearch.v0.opensearch_config import OpenSearchConfig
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_tls import OpenSearchTLS
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
)
from ops.charm import CharmBase
from ops.model import ActiveStatus, MaintenanceStatus

# The unique Charmhub library identifier, never change it
LIBID = "cba015bae34642baa1b6bb27bb35a2f7"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


PEER = "opensearch-peers"


logger = logging.getLogger(__name__)


class StatusCheckPattern(BaseStrEnum):
    """Enum for types of status comparison."""

    Equal = "equal"
    Start = "start"
    End = "end"
    Contain = "contain"
    Interpolated = "interpolated"


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

    def on_suggestion_horizontal_scale_up(self, unassigned_shards: int):
        """Called during node shutdown / horizontal scale-down if some shards left unassigned."""
        self.app.status = MaintenanceStatus(HorizontalScaleUpSuggest.format(unassigned_shards))

    def on_tls_conf_set(
        self, event: CertificateAvailableEvent, scope: Scope, cert_type: CertType, renewal: bool
    ) -> None:
        """Called after certificate ready and stored on the corresponding scope databag."""
        pass

    def on_tls_relation_broken(self):
        """Called after certificates relation broken."""
        pass

    def clear_status(
        self, status_message: str, pattern: StatusCheckPattern = StatusCheckPattern.Equal
    ):
        """Resets the unit status if it was previously blocked/maintenance with message."""
        condition: bool
        if pattern == StatusCheckPattern.Equal:
            condition = self.unit.status.message == status_message
        elif pattern == StatusCheckPattern.Start:
            condition = self.unit.status.message.startswith(status_message)
        elif pattern == StatusCheckPattern.End:
            condition = self.unit.status.message.endswith(status_message)
        elif pattern == StatusCheckPattern.Interpolated:
            condition = (
                re.fullmatch(status_message.replace("{}", "(?s:.*?)"), status_message) is not None
            )
        else:
            condition = status_message in self.unit.status.message

        if condition:
            self.unit.status = ActiveStatus()

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

    @property
    def unit_id(self) -> int:
        """ID of the current unit."""
        return int(self.unit.name.split("/")[1])

    @property
    def alternative_host(self) -> str:
        """Return an alternative host (of another node) in case the current is offline."""
        all_units_ips = units_ips(self, PEER)
        del all_units_ips[str(self.unit_id)]

        return random.choice(list(all_units_ips.values()))

    def _get_relation_data(self, scope: Scope, relation_name: str) -> Dict[str, str]:
        """Relation data object."""
        relation = self.model.get_relation(relation_name)
        if relation is None:
            return {}

        relation_scope = self.app if scope == Scope.APP else self.unit

        return relation.data[relation_scope]
