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

TODO add databag reference information
"""

import json
import logging
from typing import Dict, List

from charms.data_platform_libs.v0.data_interfaces import (
    IndexRequestedEvent,
    OpenSearchProvides,
)
from charms.opensearch.v0.constants_charm import (
    ClientRelationBadRoleRequestMessage,
    ClientRelationName,
    PeerRelationName,
)
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.helper_networking import units_ips
from charms.opensearch.v0.helper_security import generate_hashed_password
from charms.opensearch.v0.opensearch_users import OpenSearchUserMgmtError
from ops.charm import (
    CharmBase,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationDepartedEvent,
)
from ops.framework import Object
from ops.model import BlockedStatus, Relation

logger = logging.getLogger(__name__)


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

    def _on_index_requested(self, event: IndexRequestedEvent) -> None:
        """Handle client index-requested event.

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

        try:
            logger.error(event.extra_user_roles)
            extra_user_roles = json.loads(event.extra_user_roles)
        except (json.decoder.JSONDecodeError, TypeError) as err:
            # TODO document what a client application would need to provide to make this work.
            logger.error(err)
            self.unit.status = BlockedStatus(ClientRelationBadRoleRequestMessage)
            return

        username = self._relation_username(event.relation)
        hashed_pwd, pwd = generate_hashed_password()
        try:
            self.create_opensearch_users(username, hashed_pwd, extra_user_roles)
        except OpenSearchUserMgmtError as err:
            logger.error(err)
            self.unit.status = BlockedStatus(str(err))
            return

        rel_id = event.relation.id

        # Share the credentials and updated connection info with the client application.
        self.opensearch_provides.set_credentials(rel_id, username, pwd)
        self.update_endpoints(event.relation)
        self.opensearch_provides.set_version(rel_id, self.opensearch.version)
        self.update_certs(rel_id)

    def create_opensearch_users(
        self, username: str, hashed_pwd: str, access_control: Dict[str, List[str]]
    ):
        """Creates necessary opensearch users and permissions for this relation.

        Args:
            username: Username to be created
            hashed_pwd: the hash of the password to be assigned to the user
            access_control: A dict of roles, permissions, and action groups to be applied to the
                user. A new role will be created to contain the requested permissions and action
                groups.
        """
        roles = access_control.get("roles")
        permissions = access_control.get("permissions")
        action_groups = access_control.get("action_groups")

        if permissions or action_groups:
            # combine action groups and perms into a new role for this relation.
            try:
                self.user_manager.create_role(
                    role_name=username,
                    permissions=permissions,
                    action_groups=action_groups,
                )
                roles.append(username)
            except OpenSearchUserMgmtError as err:
                logger.error(err)
                raise

        try:
            self.user_manager.create_user(username, roles, hashed_pwd)
            if roles:
                self.user_manager.patch_user(
                    username,
                    [{"op": "replace", "path": "/opendistro_security_roles", "value": roles}],
                )
        except OpenSearchUserMgmtError as err:
            logger.error(err)
            raise

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
        self.opensearch_provides.set_tls(relation_id, "True")

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        self.update_endpoints(event.relation)

    def _on_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Check if this relation is being removed, and update the peer databag accordingly."""
        self.update_endpoints(event.relation)
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
        self.opensearch_provides.set_endpoints(relation.id, ",".join(endpoints))
