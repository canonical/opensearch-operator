# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch client relation hooks & helpers.

TODO @medib is this documentation correct?
The read-only-endpoints field of DatabaseProvides is unused in this relation because this concept
is irrelevant to OpenSearch - the application charm should be defining which nodes are readonly and
which are read/write.

TODO add databag reference information
TODO add tls
TODO unit tests

Databag needs client credentials and client cert
"""

import json
import logging

from charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProvides,
    DatabaseRequestedEvent,
)
from charms.opensearch.v0.constants_charm import ClientRelationName, PeerRelationName
from charms.opensearch.v0.helper_networking import units_ips
from charms.opensearch.v0.helper_security import generate_password
from charms.opensearch.v0.opensearch_users import create_role, create_user
from ops.charm import CharmBase
from ops.framework import Object
from ops.model import BlockedStatus

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
        # Rename to something like app_name_id
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

        rel_id = event.relation.id
        username = self._relation_username(rel_id)

        try:
            extra_user_roles = json.loads(event.extra_user_roles)
            # TODO document that only default roles and action groups can be specified
            roles = extra_user_roles.get("roles")
            permissions = extra_user_roles.get("permissions")
            action_groups = extra_user_roles.get("action_groups")

        except json.decoder.JSONDecodeError:
            # TODO document what a client application would need to provide to make this work.
            self.charm.status = BlockedStatus(
                "bad relation request - client application has not provided correctly formatted extra user roles. "
            )
            return

        # create role mapping of all roles, new and default, and apply to new user.
        if permissions or action_groups:
            # combine agroups and perms into a new role of all perms given.
            # TODO make new role with "username" as the name, combining permissions of action
            # groups and permissions given.
            create_role(
                self.opensearch,
                role_name=username,
                permissions=permissions,
                action_groups=action_groups,
            )

            # TODO Save role somewhere we can guarantee that we'll be able to delete it later.
            roles.add(username)

        # generate user with roles
        password = generate_password()
        create_user(username, roles, password, with_cert=False)
        # create mapping of users to roles

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
