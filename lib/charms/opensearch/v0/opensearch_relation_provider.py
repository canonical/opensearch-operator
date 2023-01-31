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

import json
import logging

from charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProvides,
    DatabaseRequestedEvent,
)
from charms.opensearch.v0.constants_charm import ClientRelationName, PeerRelationName
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.helper_networking import units_ips
from charms.opensearch.v0.helper_security import generate_hashed_password
from charms.opensearch.v0.opensearch_users import (
    OpenSearchUserMgmtError,
    create_role,
    create_user,
    remove_role,
    remove_user,
)
from ops.charm import CharmBase, RelationBrokenEvent, RelationDepartedEvent
from ops.framework import Object
from ops.model import BlockedStatus, Relation

logger = logging.getLogger(__name__)


class OpenSearchProvider(Object):
    """Defines functionality for the 'provides' side of the 'pgbouncer-client' relation.

    Hook events observed:
        - database-requested
        - relation-departed
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
            charm.on[self.relation_name].relation_departed, self._on_relation_departed
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_broken, self._on_relation_broken
        )

    def _relation_username(self, relation: Relation) -> str:
        return f"{self.relation_name}_{relation.id}_user"

    def _depart_flag(self, relation: Relation):
        return f"{self.relation_name}_{relation.id}_departing"

    def _unit_departing(self, relation):
        return self.charm.peers_data.get(Scope.UNIT, self._depart_flag(relation)) == "true"

    def _on_database_requested(self, event: DatabaseRequestedEvent) -> None:
        """Handle client database-requested event.

        TODO @medib is this documentation correct?
        The read-only-endpoints field of DatabaseProvides is unused in this relation because this
        concept is irrelevant to OpenSearch - the application charm should be defining which nodes
        are readonly and which are read/write.
        """
        if not self.unit.is_leader():
            return
        if not self.opensearch.is_node_up():
            event.defer()
            return

        try:
            # TODO add a case for when extra_user_roles is empty
            extra_user_roles = json.loads(event.extra_user_roles)
        except (json.decoder.JSONDecodeError, TypeError):
            # TODO document what a client application would need to provide to make this work.
            self.unit.status = BlockedStatus(
                "bad relation request - client application has not provided correctly formatted extra user roles. "
            )
            return

        username = self._relation_username(event.relation)
        # TODO document that only default roles and action groups can be specified
        roles = extra_user_roles.get("roles")
        permissions = extra_user_roles.get("permissions")
        action_groups = extra_user_roles.get("action_groups")
        if permissions or action_groups:
            # combine agroups and perms into a new role of all perms given.
            try:
                create_role(
                    self.opensearch,
                    role_name=username,
                    permissions=permissions,
                    action_groups=action_groups,
                )
                roles.append(username)
            except OpenSearchUserMgmtError:
                self.unit.status = BlockedStatus("bad relation request - role creation failed.")

        # generate user with roles
        hashed_pwd, pwd = generate_hashed_password()
        try:
            create_user(
                self.opensearch,
                username,
                roles,
                hashed_pwd,
            )
        except OpenSearchUserMgmtError:
            self.unit.status = BlockedStatus("bad relation request - user creation failed. ")

        rel_id = event.relation.id
        # Share the credentials and updated connection info with the client application.
        self.database_provides.set_credentials(rel_id, username, pwd)
        self.update_endpoints(event.relation)
        self.database_provides.set_version(rel_id, self.opensearch.version())

    def _on_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Check if this relation is being removed, and update the peer databag accordingly."""
        if event.departing_unit == self.charm.unit:
            self.charm.peers_data.put(Scope.UNIT, self._depart_flag(event.relation), "true")

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle client relation-broken event."""
        if not self.opensearch.is_node_up() or not self.unit.is_leader():
            return
        if self._unit_departing(event.relation):
            # This unit is being removed, so don't update the relation.
            self.charm.peers_data.delete(Scope.UNIT, self._depart_flag(event.relation))
            return

        try:
            remove_user(self.opensearch, self._relation_username(event.relation))
            remove_role(self.opensearch, self._relation_username(event.relation))
        except OpenSearchUserMgmtError:
            self.unit.status = BlockedStatus("bad relation request - user/role removal failed. ")

    def update_endpoints(self, relation):
        """Updates endpoints in the databag for the given relation."""
        port = self.opensearch.port
        endpoints = [f"{ip}:{port}" for ip in units_ips(self.charm, PeerRelationName).values()]
        self.database_provides.set_endpoints(relation.id, ",".join(endpoints))
