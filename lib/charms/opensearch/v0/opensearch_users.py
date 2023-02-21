# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch user helper functions.

These functions wrap around some API calls used for user management.
"""

import logging
from typing import Dict, List, Optional, Set

from charms.opensearch.v0.constants_charm import ClientRelationName, OpenSearchUsers
from charms.opensearch.v0.opensearch_distro import OpenSearchHttpError
from ops.framework import Object

logger = logging.getLogger(__name__)


USER_ENDPOINT = "/_plugins/_security/api/internalusers"
ROLE_ENDPOINT = "/_plugins/_security/api/roles"


class OpenSearchUserMgmtError(Exception):
    """Base exception class for OpenSearch user management errors."""


class OpenSearchUserManager:
    """User management class for OpenSearch API."""

    def __init__(self, charm):
        self.charm = charm
        self.model = charm.model
        self.unit = self.charm.unit
        self.opensearch = self.charm.opensearch

    def get_roles(self) -> Dict[str, any]:
        """Gets list of roles.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        return self.opensearch.request("GET", f"{ROLE_ENDPOINT}/")

    def create_role(
        self,
        role_name: str,
        permissions: Optional[Dict[str, str]],
        action_groups: Optional[Dict[str, str]],
    ) -> Dict[str, any]:
        """Creates a role with the given permissions.

        This method assumes the dicts provided are valid opensearch config. If not, raises
        OpenSearchUserMgmtError.

        Args:
            role_name: name of the role
            permissions: A valid dict of existing opensearch permissions.
            action_groups: A valid dict of existing opensearch action groups.

        Raises:
            OpenSearchUserMgmtError: If the role creation request fails.
        """
        resp = self.opensearch.request(
            "PUT",
            f"{ROLE_ENDPOINT}/{role_name}",
            {**(permissions or {}), **(action_groups or {})},
        )
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"creating role {role_name} failed")
        return resp

    def remove_role(self, role_name: str) -> Dict[str, any]:
        """Remove the given role from opensearch distribution.

        Args:
            role_name: name of the role to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if role_name is empty
        """
        if not role_name:
            raise OpenSearchUserMgmtError(
                "role name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        resp = self.opensearch.request("DELETE", f"{ROLE_ENDPOINT}/{role_name}")
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing role {role_name} failed")
        return resp

    def get_users(self) -> Dict[str, any]:
        """Gets list of users.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        return self.opensearch.request("GET", f"{USER_ENDPOINT}/")

    def create_user(
        self, user_name: str, roles: Optional[List[str]], hashed_pwd: str
    ) -> Dict[str, any]:
        """Create or update user and assign the requested roles to the user.

        Args:
            user_name: name of the user to be created.
            roles: list of roles to be applied to the user. These must already exist.
            hashed_pwd: the hashed password for the user.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        payload = {"hash": hashed_pwd}
        if roles:
            payload["opendistro_security_roles"] = roles

        resp = self.opensearch.request(
            "PUT",
            f"{USER_ENDPOINT}/{user_name}",
            payload,
        )
        if resp.get("status") != "CREATED":
            raise OpenSearchUserMgmtError(f"creating user {user_name} failed")
        return resp

    def remove_user(self, user_name: str) -> Dict[str, any]:
        """Remove the given user from opensearch distribution.

        Args:
            user_name: name of the user to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if user_name is empty
        """
        if not user_name:
            raise OpenSearchUserMgmtError(
                "user name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        resp = self.opensearch.request("DELETE", f"{USER_ENDPOINT}/{user_name}/")
        # TODO update to handle if the user doesn't exist
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing user {user_name} failed")
        return resp

    def patch_user(self, user_name: str, patches: List[Dict[str, any]]) -> Dict[str, any]:
        """Applies patches to user.

        Args:
            user_name: name of the user to be created.
            patches: a list of patches to be applied to the user in question.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        resp = self.opensearch.request(
            "PATCH",
            f"{USER_ENDPOINT}/{user_name}",
            patches,
        )
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"patching user {user_name} failed")
        return resp

    def remove_users_and_roles(self, departed_relation_id: Optional[int] = None):
        """Removes lingering relation users and roles from opensearch.

        Args:
            departed_relation_id: if a relation is departing, pass in the ID and its user will be
                deleted.
        """
        if not self.opensearch.is_node_up() or not self.unit.is_leader():
            return

        relations = self.model.relations.get(ClientRelationName, [])
        relation_users = set(
            [
                f"{ClientRelationName}_{relation.id}"
                for relation in relations
                if relation.id != departed_relation_id
            ]
        )
        self._remove_lingering_users(relation_users)
        self._remove_lingering_roles(relation_users)

    def _remove_lingering_users(self, relation_users: Set[str]):
        app_users = relation_users | OpenSearchUsers
        try:
            database_users = set(self.get_users().keys())
        except OpenSearchUserMgmtError:
            logger.error("failed to get users")
            return

        for username in database_users - app_users:
            try:
                self.remove_user(username)
            except OpenSearchUserMgmtError:
                logger.error(f"failed to remove user {username}")

    def _remove_lingering_roles(self, roles: Set[str]):
        try:
            database_roles = set(self.get_roles().keys())
        except (OpenSearchUserMgmtError, OpenSearchHttpError):
            logger.error("failed to get roles")
            return

        for role in database_roles - roles:
            if not role.startswith(f"{ClientRelationName}_"):
                # This role was not created by this charm, so leave it alone
                continue
            try:
                self.remove_role(role)
            except OpenSearchUserMgmtError:
                logger.error(f"failed to remove role {role}")
