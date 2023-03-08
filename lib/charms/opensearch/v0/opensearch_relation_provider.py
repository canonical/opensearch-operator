# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch client relation hooks & helpers.

The read-only-endpoints field of DatabaseProvides is unused in this relation because this concept
is irrelevant to OpenSearch. In this relation, the application charm should have control over node
& index security policies, and therefore differentiating between types of network endpoints is
unnecessary.

A role will be created for the relation with the permissions and action groups applied, and these
roles will be mapped to a dedicated user for the relation, which will be removed with the relation.
Default security values can be found in the opensearch documentation here:
https://opensearch.org/docs/latest/security/access-control/index/.

"""

import logging
from enum import Enum

from charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProvides,
    DatabaseRequestedEvent,
)
from charms.opensearch.v0.constants_charm import (
    ClientRelationName,
    PeerRelationName,
)
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.helper_networking import units_ips
from charms.opensearch.v0.helper_security import generate_hashed_password
from charms.opensearch.v0.opensearch_users import OpenSearchUserMgmtError
from ops.charm import CharmBase, RelationBrokenEvent, RelationDepartedEvent
from ops.framework import Object
from ops.model import BlockedStatus, Relation

logger = logging.getLogger(__name__)

# The unique Charmhub library identifier, never change it
LIBID = "c0f1d8f94bdd41a781fe2871e1922480"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class ExtraUserRole:
    def __init__(self, extra_user_roles: str, index: str):
        self.index = index
        try:
            self.permissions = ExtraUserRolePermissions[extra_user_roles.upper()]
        except TypeError:
            logger.error("invalid extra_user_roles parameter supplied to relation")
            raise

class ExtraUserRolePermissions(Enum):
    """An enum of user types and their associated permissions."""

    # Default user has CRUD in a specific index. Update index_patterns to include the index.
    DEFAULT = {
        "cluster_permissions": ["cluster_monitor"],
        "index_permissions": [
            {
                "index_patterns": [TODO index name goes here],
                "dls": "",
                "fls": [],
                "masked_fields": [],
                "allowed_actions": [
                    "indices_monitor",
                    "create_index",
                    "crud",
                    "data_access",
                    "indices:data/read/search",
                    "indices:admin/create",
                ],
            }
        ],
    }

    # Admin user has control over:
    # - creating multiple indices
    # - creating and deleting users and assigning their access controls
    # - Removing indices they have created
    # - Node roles
    ADMIN = {}

    def set_index(self, index_name: str):
        """Set these permissions for a specific index."""
        for perm_set in self["index_permissions"]:
            perm_set["index_patterns"] = index_name


class OpenSearchProvider(Object):
    """Defines functionality for the 'provides' side of the 'opensearch-client' relation.

    Hook events observed:
        - database-requested
        - relation-departed
        - relation-broken
    """

    def __init__(self, charm: CharmBase) -> None:
        """Constructor for OpenSearchProvider object.

        Args:
            charm: the charm for which this relation is provided
        """
        super().__init__(charm, ClientRelationName)

        self.charm = charm
        self.unit = self.charm.unit
        self.app = self.charm.app
        self.opensearch = self.charm.opensearch
        self.user_manager = self.charm.user_manager

        self.relation_name = ClientRelationName
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
        return f"{self.relation_name}_{relation.id}"

    def _depart_flag(self, relation: Relation):
        return f"{self.relation_name}_{relation.id}_departing"

    def _unit_departing(self, relation):
        return self.charm.peers_data.get(Scope.UNIT, self._depart_flag(relation))

    def _on_database_requested(self, event: DatabaseRequestedEvent) -> None:
        """Handle client database-requested event.

        The read-only-endpoints field of DatabaseProvides is unused in this relation because this
        concept is irrelevant to OpenSearch. In this relation, the application charm should have
        control over node & index security policies, and therefore differentiating between types of
        network endpoints is unnecessary.
        """
        if not self.unit.is_leader():
            return
        if not self.opensearch.is_node_up():
            event.defer()
            return

        username = self._relation_username(event.relation)
        hashed_pwd, pwd = generate_hashed_password()
        try:
            self.create_opensearch_users(username, hashed_pwd, event.index, user_roles)
        except OpenSearchUserMgmtError as err:
            logger.error(err)
            self.unit.status = BlockedStatus(str(err))
            return

        rel_id = event.relation.id
        # Share the credentials and updated connection info with the client application.
        self.database_provides.set_credentials(rel_id, username, pwd)
        self.update_endpoints(event.relation)
        self.database_provides.set_version(rel_id, self.opensearch.version)

    def create_opensearch_users(
        self, username: str, hashed_pwd: str, index: str, extra_user_roles: ExtraUserRolePermissions
    ):
        """Creates necessary opensearch users and permissions for this relation.

        Args:
            username: Username to be created
            hashed_pwd: the hash of the password to be assigned to the user
            access_control: A dict of roles, permissions, and action groups to be applied to the
                user. A new role will be created to contain the requested permissions and action
                groups.

        Raises:
            OpenSearchUserMgmtError if user creation fails
        """
        # TODO this might be setting the values inside the enum?
        extra_user_roles.set_index(index)
        try:
            # Create a new role for this relation, encapsulating the permissions we care about. We
            # can't create a "default" and an "admin" role once because the permissions need to be
            # set to this relation's specific index.
            self.user_manager.create_role(
                role_name=username,
                permissions=extra_user_roles.value,
            )
            self.user_manager.create_user(username, [username], hashed_pwd)
            self.user_manager.patch_user(
                username,
                [{"op": "replace", "path": "/opendistro_security_roles", "value": [username]}],
            )
        except OpenSearchUserMgmtError as err:
            logger.error(err)
            raise

    def _on_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Check if this relation is being removed, and update the peer databag accordingly."""
        if event.departing_unit == self.charm.unit:
            self.charm.peers_data.put(Scope.UNIT, self._depart_flag(event.relation), True)

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle client relation-broken event."""
        if not self.unit.is_leader():
            return
        if self._unit_departing(event.relation):
            # This unit is being removed, so don't update the relation.
            self.charm.peers_data.delete(Scope.UNIT, self._depart_flag(event.relation))
            return

        self.user_manager.remove_users_and_roles(event.relation.id)

    def update_endpoints(self, relation):
        """Updates endpoints in the databag for the given relation."""
        port = self.opensearch.port
        endpoints = [f"{ip}:{port}" for ip in units_ips(self.charm, PeerRelationName).values()]
        self.database_provides.set_endpoints(relation.id, ",".join(endpoints))
