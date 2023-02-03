# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch user helper functions.

These functions wrap around some API calls used for user management.
"""

import logging
from typing import Dict, List, Optional

from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution

logger = logging.getLogger(__name__)


USER_ENDPOINT = "/_plugins/_security/api/internalusers"
ROLE_ENDPOINT = "/_plugins/_security/api/roles"


class OpenSearchUserMgmtError(Exception):
    """Base exception class for OpenSearch user management errors."""


class OpenSearchUserManager:
    """User management class for OpenSearch API."""

    def __init__(self, opensearch: OpenSearchDistribution):
        self.opensearch = opensearch

    def create_role(
        self,
        role_name: str,
        permissions: Optional[Dict[str, str]],
        action_groups: Optional[Dict[str, str]],
    ) -> None:
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
        put_role_resp = self.opensearch.request(
            "PUT",
            f"{ROLE_ENDPOINT}/{role_name}",
            {**(permissions or {}), **(action_groups or {})},
        )
        logger.debug(put_role_resp)
        if put_role_resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(
                f"creating role {role_name} failed - response: {put_role_resp}"
            )

    def remove_role(self, role_name: str) -> None:
        """Remove the given role from opensearch distribution.

        Args:
            role_name: name of the role to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        resp = self.opensearch.request("DELETE", f"{ROLE_ENDPOINT}/{role_name}")
        logger.debug(resp)
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing role {role_name} failed - response: {resp}")

    def create_user(self, user_name: str, roles: Optional[List[str]], hashed_pwd: str) -> None:
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

        put_user_resp = self.opensearch.request(
            "PUT",
            f"{USER_ENDPOINT}/{user_name}",
            payload,
        )
        logger.debug(put_user_resp)
        if put_user_resp.get("status") != "CREATED":
            raise OpenSearchUserMgmtError(
                f"creating user {user_name} failed - response: {put_user_resp}"
            )

    def remove_user(self, user_name: str) -> None:
        """Remove the given user from opensearch distribution.

        Args:
            user_name: name of the user to be removed.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        resp = self.opensearch.request("DELETE", f"{USER_ENDPOINT}/{user_name}/")
        logger.debug(resp)
        if resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(f"removing user {user_name} failed - response: {resp}")

    def patch_user(self, user_name: str, patches: List[Dict[str, any]]) -> None:
        """Applies patches to user.

        Args:
            user_name: name of the user to be created.
            patches: a list of patches to be applied to the user in question.

        Raises:
            OpenSearchUserMgmtError: If the request fails.
        """
        patch_user_resp = self.opensearch.request(
            "PATCH",
            f"{USER_ENDPOINT}/{user_name}",
            patches,
        )
        logger.debug(patch_user_resp)
        if patch_user_resp.get("status") != "OK":
            raise OpenSearchUserMgmtError(
                f"patching user {user_name} failed - response: {patch_user_resp}"
            )
