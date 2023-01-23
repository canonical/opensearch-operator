# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch client relation hooks & helpers.

TODO @medib is this documentation correct?
The read-only-endpoints field of DatabaseProvides is unused in this relation because this concept
is irrelevant to OpenSearch - the application charm should be defining which nodes are readonly and
which are read/write.

TODO add databag reference information
TODO add tls

Databag needs client credentials and client cert
"""

import logging

from charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProvides,
    DatabaseRequestedEvent,
)
from charms.opensearch.v0.constants_charm import ClientRelationName, PeerRelationName
from charms.opensearch.v0.helper_networking import units_ips
from charms.opensearch.v0.helper_security import generate_password
from ops.charm import CharmBase
from ops.framework import Object

logger = logging.getLogger(__name__)


class OpenSearchProvider(Object):
    """Defines functionality for the 'provides' side of the 'pgbouncer-client' relation.

    Hook events observed:
        - database-requested
        - relation-broken
    """

    def __init__(self, charm: CharmBase, relation_name: str = ClientRelationName) -> None:
        """Constructor for PgbouncerProvider object.

        Args:
            charm: the charm for which this relation is provided
            relation_name: the name of the relation
        """
        super().__init__(charm, relation_name)

        self.charm = charm
        self.unit = self.charm.unit
        self.app = self.charm.app
        self.opensearch = self.charm.opensearch

        self.relation_name = relation_name
        self.database_provides = DatabaseProvides(self.charm, relation_name=self.relation_name)

        self.framework.observe(
            self.database_provides.on.database_requested, self._on_database_requested
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_broken, self._on_relation_broken
        )

    def _relation_username(self, relation_id: int) -> str:
        return f"{self.relation_name}_relation_{relation_id}_user"

    def _on_database_requested(self, event: DatabaseRequestedEvent) -> None:
        """Handle client database-requested event.

        TODO @medib is this documentation correct?
        The read-only-endpoints field of DatabaseProvides is unused in this relation because this
        concept is irrelevant to OpenSearch - the application charm should be defining which nodes
        are readonly and which are read/write.
        """
        if not self.unit.is_leader():
            return

        # check app is ready to roll, defer if not
        if not self.opensearch.is_node_up():
            event.defer()
            return

        # Retrieve the database name and extra user roles using the charm library.
        # index = event.database
        # extra_user_roles = event.extra_user_roles
        rel_id = event.relation.id
        username = self._relation_username(rel_id)
        password = generate_password()

        # generate db client
        # generate user with roles

        # Share the credentials and updated connection info with the client application.
        self.database_provides.set_credentials(rel_id, username, password)
        self.update_endpoints()
        self.database_provides.set_version(rel_id, self.opensearch.version())

    def _on_relation_broken(self, _) -> None:
        """Handle client relation-broken event."""
        # TODO check whether this unit is being removed, or this relation. If the unit's being
        # removed, do nothing, but if this relation is being removed, then continue.
        if not self.unit.opensearch.is_node_up():
            # TODO check whether to defer here.
            return

        # deauth user

    def update_endpoints(self, relation):
        """Updates endpoints in the databag for the given relation."""
        port = self.opensearch.port
        ips = [f"{ip}:{port}" for ip in units_ips(self.charm, PeerRelationName).values()]
        self.database_provides.set_endpoints(relation.id, ",".join(ips))
