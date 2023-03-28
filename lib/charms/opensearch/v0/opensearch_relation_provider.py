# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch client relation hooks & helpers.

See this link for a detailed spec:
https://github.com/canonical/charm-relation-interfaces/tree/main/interfaces/opensearch_client/v0

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
from typing import Dict, Optional, Set

from charms.data_platform_libs.v0.data_interfaces import (
    IndexRequestedEvent,
    OpenSearchProvides,
)
from charms.opensearch.v0.constants_charm import ClientRelationName
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.helper_security import generate_hashed_password
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchHttpError,
    OpenSearchIndexError,
)
from charms.opensearch.v0.opensearch_users import OpenSearchUserMgmtError
from ops.charm import (
    CharmBase,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationDepartedEvent,
)
from ops.framework import Object
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, Relation

# The unique Charmhub library identifier, never change it
LIBID = "c0f1d8f94bdd41a781fe2871e1922480"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


INVALID_INDEX_NAMES = [
    ".opendistro_security",
    ".opendistro-alerting-config",
    ".opendistro-alerting-alert*",
    ".opendistro-anomaly-results*",
    ".opendistro-anomaly-detector*",
    ".opendistro-anomaly-checkpoints",
    ".opendistro-anomaly-detection-state",
]


class ExtraUserRolePermissions(Enum):
    """An enum of user types and their associated permissions."""

    # Default user has CRUD in a specific index. Update index_patterns to include the index to
    # which these permissions are applied.
    DEFAULT = {
        "cluster_permissions": ["cluster_monitor"],
        "index_permissions": [
            {
                "index_patterns": [],
                "dls": "",
                "fls": [],
                "masked_fields": [],
                "allowed_actions": [
                    "indices_monitor",
                    "data_access",
                ],
            }
        ],
    }

    # Admin user has control over:
    # - creating multiple indices
    # - Removing indices they have created
    ADMIN = {
        "index_permissions": [
            {
                "index_patterns": ["*"],
                "fls": [],
                "masked_fields": [],
                "allowed_actions": [
                    "cluster_all",
                    "indices_all",
                    "crud",
                ],
            }
        ],
        "cluster_permissions": [
            "indices_all",
            "cluster_all",
            "manage",
        ],
    }


class OpenSearchProvider(Object):
    """Defines functionality for the 'provides' side of the 'opensearch-client' relation.

    Hook events observed:
        - index-requested
        - relation-departed
        - relation-broken
    """

    def __init__(self, charm: CharmBase) -> None:
        """Constructor for OpenSearchProvider object.

        Args:
            charm: the charm providing the opensearch relation
        """
        super().__init__(charm, ClientRelationName)

        self.charm = charm
        self.unit = self.charm.unit
        self.app = self.charm.app
        self.opensearch = self.charm.opensearch
        self.user_manager = self.charm.user_manager

        self.relation_name = ClientRelationName
        self.opensearch_provides = OpenSearchProvides(self.charm, relation_name=self.relation_name)
        self.relations = self.opensearch_provides.relations

        self.framework.observe(
            self.opensearch_provides.on.index_requested, self._on_index_requested
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

    def _on_index_requested(self, event: IndexRequestedEvent) -> None:  # noqa
        """Handle client index-requested event.

        The read-only-endpoints field of DatabaseProvides is unused in this relation because this
        concept is irrelevant to OpenSearch. In this relation, the application charm should have
        control over node & index security policies, and therefore differentiating between types of
        network endpoints is unnecessary.

        Raises:
            OpenSearchIndexError if the index name is invalid
            OpenSearchHttpError if we can't create the required index
        """
        if not self.unit.is_leader():
            return
        if not self.opensearch.is_node_up() or not event.index:
            event.defer()
            return

        if not self.validate_index_name(event.index):
            raise OpenSearchIndexError(f"invalid index name: {event.index}")

        self.unit.status = MaintenanceStatus(f"new index {event.index} requested")

        # Check if index exists before trying to create it. Returns 200 if exists, 404 if not.
        try:
            index_exists = self.opensearch.request(
                "HEAD", f"/{event.index}", resp_status_code=True
            )
        except OpenSearchHttpError as e:
            index_exists = e.response_code

        try:
            if index_exists != 200:
                self.opensearch.request("PUT", f"/{event.index}")
        except OpenSearchHttpError as e:
            if not (
                e.response_code == 400
                and e.response_body.get("error", {}).get("type")
                == "resource_already_exists_exception"
            ):
                logger.error(e)
                raise

        username = self._relation_username(event.relation)
        hashed_pwd, pwd = generate_hashed_password()
        extra_user_roles = event.extra_user_roles.lower() if event.extra_user_roles else "default"
        try:
            self.create_opensearch_users(username, hashed_pwd, event.index, extra_user_roles)
        except OpenSearchUserMgmtError as err:
            logger.error(err)
            self.unit.status = BlockedStatus(str(err))
            return

        rel_id = event.relation.id

        # Share the credentials and updated connection info with the client application.
        self.opensearch_provides.set_version(rel_id, self.opensearch.version)
        self.opensearch_provides.set_credentials(rel_id, username, pwd)
        self.opensearch_provides.set_index(rel_id, event.index)
        self.update_certs(rel_id)
        self.update_endpoints(event.relation)
        self.unit.status = ActiveStatus(f"new index {event.index} requested")

    def validate_index_name(self, index_name: str) -> bool:
        """Validates that the index name provided in the relation is acceptable."""
        if index_name in INVALID_INDEX_NAMES:
            logger.error(
                f"invalid index name {index_name} - tried to access a protected index in {INVALID_INDEX_NAMES}"
            )
            return False

        if not index_name.islower():
            logger.error(f"invalid index name {index_name} - index names must be lowercase")
            return False

        invalid_chars = [" ", ",", ":", '"', "*", "+", "\\", "/", "|", "?", "#", ">", "<"]
        if any([char in index_name for char in invalid_chars]):
            logger.error(
                f"invalid index name {index_name} - index name includes one or more of the following invalid characters: {invalid_chars}"
            )
            return False

        return True

    def create_opensearch_users(
        self,
        username: str,
        hashed_pwd: str,
        index: str,
        extra_user_roles: str,
    ):
        """Creates necessary opensearch users and permissions for this relation.

        Args:
            username: Username to be created
            hashed_pwd: the hash of the password to be assigned to the user
            index: the index to which the users must be granted access
            extra_user_roles: the level of permissions that the user should be given. Can be a
                comma-separated list of roles, which should result in a merged list of permissions.

        Raises:
            OpenSearchUserMgmtError if user creation fails
        """
        try:
            # Create a new role for this relation, encapsulating the permissions we care about. We
            # can't create a "default" and an "admin" role once because the permissions need to be
            # set to this relation's specific index.
            self.user_manager.create_role(
                role_name=username,
                permissions=self.get_extra_user_role_permissions(extra_user_roles, index),
            )
            roles = [username]
            self.user_manager.create_user(username, roles, hashed_pwd)
            self.user_manager.patch_user(
                username,
                [
                    {"op": "replace", "path": "/.opendistro_security_roles", "value": roles},
                    {"op": "replace", "path": "/backend_roles", "value": roles},
                ],
            )
        except OpenSearchUserMgmtError as err:
            logger.error(err)
            raise

    def get_extra_user_role_permissions(self, extra_user_roles: str, index: str) -> Dict[str, any]:
        """Get relation role permissions from the extra_user_roles field.

        Args:
            extra_user_roles: role requested by the requirer unit, provided in relation databag.
                This needs to be one of "admin" or "default", or it will be set to "default".
                TODO should this fail and raise an error instead so provider charm authors can
                guarantee they're getting the perms they expect?
            index: if these permissions are index-specific, they will be assigned to this index.

        Returns:
            A dict containing the required permissions for the requested role.
        """
        roles = set(extra_user_roles.split(","))
        permissions = ExtraUserRolePermissions.DEFAULT.value

        # Merge the permissions for all roles into one permissions dict. Currently no checking if
        # this would create an invalid role config.
        for role in roles:
            if role.upper() in ExtraUserRolePermissions._member_names_:
                for perm_scope, perms in ExtraUserRolePermissions[role.upper()].value.items():
                    permissions[perm_scope] += perms

        for perm_set in permissions["index_permissions"]:
            # If this isn't a set of admin permissions (which applies to all indices) then set it
            # to index.
            if perm_set["index_patterns"] == []:
                perm_set["index_patterns"] = [index]

        return permissions

    def update_certs(self, relation_id, ca_chain=None):
        """Update TLS certs passed into this relation.

        If ca_chain is not provided, it'll get the app-admin CA generated by the TLS charm.
        """
        if not self.unit.is_leader():
            # We're updating app databags in this function, so it can't be called on follower
            # units.
            return
        if not ca_chain:
            try:
                ca_chain = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val).get(
                    "chain"
                )
            except AttributeError:
                # cert doesn't exist - presumably we don't yet have a TLS relation.
                return
        self.opensearch_provides.set_tls_ca(relation_id, "\n".join(ca_chain[::-1]))

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        if not self.unit.is_leader():
            return
        if self.opensearch.is_node_up():
            self.update_endpoints(event.relation)
        else:
            event.defer()

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

    def update_endpoints(self, relation: Relation, omit_endpoints: Optional[Set[str]] = None):
        """Updates endpoints in the databag for the given relation."""
        # we can only set endpoints if we're the leader
        if not self.unit.is_leader():
            return

        if not omit_endpoints:
            omit_endpoints = set()

        port = self.opensearch.port
        ips = set([node.ip for node in self.charm._get_nodes(use_localhost=True)])
        endpoints = ",".join([f"{ip}:{port}" for ip in ips - omit_endpoints])
        databag_endpoints = relation.data[relation.app].get("endpoints")

        if endpoints and endpoints != databag_endpoints:
            self.opensearch_provides.set_endpoints(relation.id, endpoints)
