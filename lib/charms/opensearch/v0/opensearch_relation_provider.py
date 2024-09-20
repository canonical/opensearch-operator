# Copyright 2024 Canonical Ltd.
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
import typing
from enum import Enum
from typing import Dict, Optional, Set

from charms.data_platform_libs.v0.data_interfaces import (
    IndexRequestedEvent,
    OpenSearchProvides,
)
from charms.opensearch.v0.constants_charm import (
    ClientRelationName,
    ClientUsersDict,
    IndexCreationFailed,
    KibanaserverRole,
    KibanaserverUser,
    NewIndexRequested,
    PeerRelationName,
    UserCreationFailed,
)
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_networking import unit_ip
from charms.opensearch.v0.helper_security import generate_hashed_password
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchHttpError,
    OpenSearchIndexError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_users import OpenSearchUserMgmtError
from ops.charm import RelationBrokenEvent, RelationChangedEvent, RelationDepartedEvent
from ops.framework import Object
from ops.model import BlockedStatus, MaintenanceStatus, Relation

if typing.TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

# The unique Charmhub library identifier, never change it
LIBID = "c0f1d8f94bdd41a781fe2871e1922480"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


PROTECTED_INDEX_NAMES = [
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

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
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
        self.secrets = self.charm.secrets

        self.relation_name = ClientRelationName
        self.opensearch_provides = OpenSearchProvides(self.charm, relation_name=self.relation_name)
        self.relations = self.opensearch_provides.relations

        self.framework.observe(
            self.opensearch_provides.on.index_requested, self._on_index_requested
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_changed, self._on_relation_changed
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_departed, self._on_relation_departed
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_broken, self._on_relation_broken
        )

    @property
    def dashboards_relations(self):
        """Return the dashboard relations out of all."""
        result = []
        for relation in self.opensearch_provides.relations:
            if (
                roles := self.opensearch_provides.fetch_relation_field(
                    relation.id, "extra-user-roles"
                )
            ) and KibanaserverRole in roles:
                # if any(key.name == "opensearch-dashboards" for key in relation.data.keys()):
                result.append(relation)
        return result

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
        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported."
                "The charm may be in a broken, unrecoverable state"
            )
            event.defer()
            return
        if not self.unit.is_leader():
            return
        if not self.opensearch.is_node_up() or not event.index:
            event.defer()
            return

        if not self.validate_index_name(event.index):
            raise OpenSearchIndexError(f"invalid index name: {event.index}")

        self.charm.status.set(MaintenanceStatus(NewIndexRequested.format(index=event.index)))
        try:
            self.opensearch.request("PUT", f"/{event.index}")
        except OpenSearchHttpError as e:
            if not (
                e.response_code == 400
                and e.response_body.get("error", {}).get("type")
                == "resource_already_exists_exception"
            ):
                logger.error(IndexCreationFailed.format(index=event.index))
                self.charm.status.set(BlockedStatus(IndexCreationFailed.format(index=event.index)))
                event.defer()
                return

        extra_user_roles = event.extra_user_roles.lower() if event.extra_user_roles else "default"
        if extra_user_roles == KibanaserverRole:
            username = KibanaserverUser
            pwd = self.secrets.get(Scope.APP, self.secrets.password_key(username))
        else:
            username = self._relation_username(event.relation)
            hashed_pwd, pwd = generate_hashed_password()
            try:
                self.create_opensearch_users(
                    username,
                    hashed_pwd,
                    event.index,
                    extra_user_roles,
                    relation_id=event.relation.id,
                )
            except OpenSearchUserMgmtError as err:
                logger.error(err)
                self.charm.status.set(
                    BlockedStatus(
                        UserCreationFailed.format(
                            rel_name=ClientRelationName, id=event.relation.id
                        )
                    )
                )
                return

        rel_id = event.relation.id

        # Share the credentials and updated connection info with the client application.
        self.opensearch_provides.set_version(rel_id, self.opensearch.version)
        self.opensearch_provides.set_credentials(rel_id, username, pwd)
        self.opensearch_provides.set_index(rel_id, event.index)
        self.update_certs(rel_id)
        self.update_endpoints(event.relation)

        logger.info(f"new index {event.index} available")
        # Clear old statuses set by this hook
        self.charm.status.clear(NewIndexRequested.format(index=event.index))
        self.charm.status.clear(IndexCreationFailed.format(index=event.index))
        self.charm.status.clear(UserCreationFailed.format(rel_name=ClientRelationName, id=rel_id))

    def validate_index_name(self, index_name: str) -> bool:
        """Validates that the index name provided in the relation is acceptable."""
        if index_name in PROTECTED_INDEX_NAMES:
            logger.error(
                f"invalid index name {index_name} - tried to access a protected index in {PROTECTED_INDEX_NAMES}"
            )
            return False

        if not index_name.islower():
            logger.error(f"invalid index name {index_name} - index names must be lowercase")
            return False

        forbidden_chars = [" ", ",", ":", '"', "*", "+", "\\", "/", "|", "?", "#", ">", "<"]
        if any([char in index_name for char in forbidden_chars]):
            logger.error(
                f"invalid index name {index_name} - index name includes one or more of "
                f"the following forbidden characters: {forbidden_chars}"
            )
            return False

        return True

    def create_opensearch_users(
        self, username: str, hashed_pwd: str, index: str, extra_user_roles: str, relation_id: int
    ):
        """Creates necessary opensearch users and permissions for this relation.

        Args:
            username: Username to be created
            hashed_pwd: the hash of the password to be assigned to the user
            index: the index to which the users must be granted access
            extra_user_roles: the level of permissions that the user should be given. Can be a
                comma-separated list of roles, which should result in a merged list of permissions.
            relation_id: the relation id for this relation, if it exists

        Raises:
            OpenSearchUserMgmtError if user creation fails
        """
        try:
            # Create a new role for this relation, encapsulating the permissions we care about. We
            # can't create a "default" and an "admin" role once because the permissions need to be
            # set to this relation's specific index.
            permissions = self.get_extra_user_role_permissions(extra_user_roles, index)
            self._put_relation_user(username, permissions, hashed_pwd, relation_id)
            self.user_manager.patch_user(
                username,
                [{"op": "replace", "path": "/opendistro_security_roles", "value": [username]}],
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
            # units. This is not checked in `set_tls_ca`, in data-interfaces.
            return
        try:
            # If the ca_chain=None, then we try to load the CA from the app-admin secret.
            _ch_chain = ca_chain or self.charm.secrets.get_object(
                Scope.APP, CertType.APP_ADMIN.val
            ).get("chain")
        except AttributeError:
            # cert doesn't exist - presumably we don't yet have a TLS relation.
            logger.warning("unable to get ca_chain")
            return
        self.opensearch_provides.set_tls_ca(relation_id, _ch_chain)

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        if not self.unit.is_leader():
            return

        if self.opensearch.is_node_up():
            self.update_endpoints(event.relation)
        else:
            event.defer()

    def _on_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Check if this relation is being removed, and update the peer databag accordingly."""
        # remove departing unit from endpoints available to requirer charm.
        if event.departing_unit.app == self.charm.app:
            departing_unit_ip = unit_ip(self.charm, event.departing_unit, PeerRelationName)
            self.update_endpoints(event.relation, omit_endpoints={departing_unit_ip})

        if event.departing_unit == self.charm.unit:
            self.charm.peers_data.put(Scope.UNIT, self._depart_flag(event.relation), True)

        self.remove_lingering_relation_users_and_roles(event.relation.id)

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle client relation-broken event."""
        if not self.unit.is_leader():
            return
        if self._unit_departing(event.relation):
            # This unit is being removed.
            self.charm.peers_data.delete(Scope.UNIT, self._depart_flag(event.relation))
            return
        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported."
                "The charm may be in a broken, unrecoverable state"
            )
        self.remove_lingering_relation_users_and_roles(event.relation.id)

    def update_endpoints(self, relation: Relation, omit_endpoints: Optional[Set[str]] = None):
        """Updates endpoints in the databag for the given relation."""
        # we can only set endpoints if we're the leader, and we can only get endpoints if the node
        # is running.
        if not self.unit.is_leader() or not self.opensearch.is_node_up() or not relation.app:
            return

        if not omit_endpoints:
            omit_endpoints = set()

        try:
            ips = set([node.ip for node in self.charm._get_nodes(use_localhost=True)])
        except OpenSearchHttpError:
            logger.error("unable to get nodes")
            ips = set()

        port = self.opensearch.port
        endpoints = ",".join(sorted([f"{ip}:{port}" for ip in ips - omit_endpoints]))
        databag_endpoints = relation.data[relation.app].get("endpoints")

        if endpoints != databag_endpoints:
            self.opensearch_provides.set_endpoints(relation.id, endpoints)

    def update_dashboards_password(self):
        """Update each Opensearch Dashboards relation with the latest kibanaserver."""
        pwd = self.secrets.get(Scope.APP, self.secrets.password_key(KibanaserverUser))
        for relation in self.dashboards_relations:
            self.opensearch_provides.set_credentials(relation.id, KibanaserverUser, pwd)

    def _put_relation_user(
        self, user: str, permissions: dict[str], hashed_pwd: str, relation_id: int
    ):
        """Create a relation user.

        Relation users are registered with a dedicated role which maps to the username,
        and their name is saved in the databag for later reference.
        """
        self.user_manager.create_role(role_name=user, permissions=permissions)
        users = self.charm.peers_data.get_object(Scope.APP, ClientUsersDict) or {}

        if users.get(relation_id):
            logger.warning(
                "User %s is already registered in Peer Relation data for relation %d.",
                user,
                relation_id,
            )

        self.user_manager.create_user(user, [user], hashed_pwd)
        users[str(relation_id)] = user
        self.charm.peers_data.put_object(Scope.APP, ClientUsersDict, users)

    def remove_lingering_relation_users_and_roles(  # noqa: C901
        self, departed_relation_id: int | None = None
    ):
        """Removes lingering relation users and roles from opensearch.

        Args:
            departed_relation_id: if a relation is departing, pass in the ID and its user will be
                deleted.
        """
        if not self.opensearch.is_node_up() or not self.unit.is_leader():
            return

        relation_users = self.charm.peers_data.get_object(Scope.APP, ClientUsersDict) or {}

        if departed_relation_id and (
            not relation_users or departed_relation_id not in relation_users
        ):
            logging.warning(
                "User for relation %d wasn't registered in internal cham workflows.",
                departed_relation_id,
            )

        clearnup_rel_ids = []
        if departed_relation_id:
            clearnup_rel_ids = [str(departed_relation_id)]

        rel_ids = [str(relation.id) for relation in self.opensearch_provides.relations]
        clearnup_rel_ids += list(set(relation_users.keys()) - set(rel_ids))

        for rel_id in clearnup_rel_ids:
            if username := relation_users.get(rel_id):
                try:
                    self.user_manager.remove_user(username)
                except OpenSearchUserMgmtError:
                    logger.error(f"failed to remove user {username}")

                try:
                    self.user_manager.remove_role(username)
                except OpenSearchUserMgmtError:
                    logger.error(f"failed to remove role {username}")

                del relation_users[rel_id]

        self.charm.peers_data.put_object(Scope.APP, ClientUsersDict, relation_users)
