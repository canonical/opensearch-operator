# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch user helper functions.

These functions wrap around some API calls used for user management.
"""

import json
import logging
from typing import Dict, List, Optional

from charms.opensearch.v0.constants_charm import (
    AdminUser,
    ClientRolesDict,
    ClientUsersDict,
    COSRole,
    COSUser,
    KibanaserverUser,
    OpenSearchUsers,
)
from charms.opensearch.v0.opensearch_distro import OpenSearchError, OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope

logger = logging.getLogger(__name__)


# The unique Charmhub library identifier, never change it
LIBID = "f9da4353bd314b86acfdfa444a9517c9"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


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
        try:
            return self.opensearch.request("GET", f"{ROLE_ENDPOINT}/")
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

    def create_role(
        self,
        role_name: str,
        permissions: Optional[Dict[str, str]] = None,
        action_groups: Optional[Dict[str, str]] = None,
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

        Returns:
            HTTP response to opensearch API request.
        """
        try:
            resp = self.opensearch.request(
                "PUT",
                f"{ROLE_ENDPOINT}/{role_name}",
                payload={**(permissions or {}), **(action_groups or {})},
            )
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            logging.error(f"Couldn't create role: {resp}")
            raise OpenSearchUserMgmtError(f"creating role {role_name} failed")

        return resp

    def remove_role(self, role_name: str) -> Dict[str, any]:
        """Remove the given role from opensearch distribution.

        Args:
            role_name: name of the role to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if role_name is empty

        Returns:
            HTTP response to opensearch API request.
        """
        if not role_name:
            raise OpenSearchUserMgmtError(
                "role name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        try:
            resp = self.opensearch.request("DELETE", f"{ROLE_ENDPOINT}/{role_name}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                return {
                    "status": "OK",
                    "response": "role does not exist, and therefore has not been removed",
                }
            else:
                raise OpenSearchUserMgmtError(e)

        logger.debug(resp)
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing role {role_name} failed")

        return resp

    def get_users(self) -> Dict[str, any]:
        """Gets list of users.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        try:
            return self.opensearch.request("GET", f"{USER_ENDPOINT}/")
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

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

        Returns:
            HTTP response to opensearch API request.
        """
        payload = {"hash": hashed_pwd}
        if roles:
            payload["opendistro_security_roles"] = roles

        try:
            resp = self.opensearch.request(
                "PUT",
                f"{USER_ENDPOINT}/{user_name}",
                payload=payload,
            )
        except OpenSearchHttpError as e:
            logger.error(f"Couldn't create user {str(e)}")
            raise OpenSearchUserMgmtError(e)

        if resp.get("status") != "CREATED" and not (
            resp.get("status") == "OK" and "updated" in resp.get("message")
        ):
            raise OpenSearchUserMgmtError(f"creating user {user_name} failed")

        return resp

    def remove_user(self, user_name: str) -> Dict[str, any]:
        """Remove the given user from opensearch distribution.

        Args:
            user_name: name of the user to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails, or if user_name is empty

        Returns:
            HTTP response to opensearch API request.
        """
        if not user_name:
            raise OpenSearchUserMgmtError(
                "user name empty - sending a DELETE request to endpoint root isn't permitted"
            )

        try:
            resp = self.opensearch.request("DELETE", f"{USER_ENDPOINT}/{user_name}")
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                return {
                    "status": "OK",
                    "response": "user does not exist, and therefore has not been removed",
                }
            else:
                raise OpenSearchUserMgmtError(e)

        logger.debug(resp)
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

        Returns:
            HTTP response to opensearch API request.
        """
        try:
            resp = self.opensearch.request(
                "PATCH",
                f"{USER_ENDPOINT}/{user_name}",
                payload=patches,
            )
        except OpenSearchHttpError as e:
            raise OpenSearchUserMgmtError(e)

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
        rel_id = str(departed_relation_id)

        relation_users = json.loads(self.charm.peers_data.get(Scope.APP, ClientUsersDict) or "{}")
        relation_roles = json.loads(self.charm.peers_data.get(Scope.APP, ClientRolesDict) or "{}")

        for username in relation_users.get(rel_id, []):
            try:
                self.remove_user(username)
            except OpenSearchUserMgmtError:
                logger.error(f"failed to remove user {username}")
        del relation_users[rel_id]

        roles_to_remove = relation_roles.get(rel_id, [])
        del relation_roles[rel_id]
        for role in roles_to_remove:
            # Check if this role is not present in any other relation:
            if any(role in r for r in relation_roles.values()):
                continue
            try:
                self.remove_role(role)
            except OpenSearchUserMgmtError:
                logger.error(f"failed to remove role {role}")

        self.charm.peers_data.put(Scope.APP, ClientUsersDict, json.dumps(relation_users))
        self.charm.peers_data.put(Scope.APP, ClientRolesDict, json.dumps(relation_roles))

    def update_user_password(self, username: str, hashed_pwd: str = None):
        """Change user hashed password."""
        resp = self.opensearch.request(
            "PATCH",
            f"/_plugins/_security/api/internalusers/{username}",
            [{"op": "replace", "path": "/hash", "value": hashed_pwd}],
        )
        if resp.get("status") != "OK":
            raise OpenSearchError(f"{resp}")

    def put_internal_user(self, user: str, hashed_pwd: str):
        """User creation for specific system users."""
        if user not in OpenSearchUsers:
            raise OpenSearchError(f"User {user} is not an internal user.")

        if user == AdminUser:
            # reserved: False, prevents this resource from being update-protected from:
            # updates made on the dashboard or the rest api.
            # we grant the admin user all opensearch access + security_rest_api_access
            self.opensearch.config.put(
                "opensearch-security/internal_users.yml",
                "admin",
                {
                    "hash": hashed_pwd,
                    "reserved": False,
                    "backend_roles": [AdminUser],
                    "opendistro_security_roles": [
                        "security_rest_api_access",
                        "all_access",
                    ],
                    "description": "Admin user",
                },
            )
        elif user == KibanaserverUser:
            self.opensearch.config.put(
                "opensearch-security/internal_users.yml",
                f"{KibanaserverUser}",
                {
                    "hash": hashed_pwd,
                    "reserved": False,
                    "description": "Kibanaserver user",
                },
            )
        elif user == COSUser:
            roles = [COSRole]
            self.create_user(COSUser, roles, hashed_pwd)
            self.patch_user(
                COSUser,
                [{"op": "replace", "path": "/opendistro_security_roles", "value": roles}],
            )
