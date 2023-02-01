# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch user helpers.

TODO update tests
"""

import logging
from typing import Any, Dict, List

from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution

logger = logging.getLogger(__name__)


USER_ENDPOINT = "/_plugins/_security/api/internalusers"
ROLE_ENDPOINT = "/_plugins/_security/api/roles"


class OpenSearchUserMgmtError(Exception):
    """Base exception class for OpenSearch user management errors."""


def create_role(
    opensearch: OpenSearchDistribution,
    role_name: str,
    permissions: Dict = {},
    action_groups: Dict = {},
) -> Dict[str, Any]:
    """Creates a role with the given permissions.

    This method assumes the dicts provided are valid opensearch config. If not, raises
    OpenSearchUserMgmtError.

    Args:
        opensearch: Opensearch distribution object, used to send requests
        role_name: name of the role
        permissions: A valid dict of existing opensearch permissions.
        action_groups: A valid dict of existing opensearch action groups.

    Raises:
        OpenSearchUserMgmtError: If the role creation request fails.

    Returns:
        Output of the role creation request.
    """
    put_role_resp = opensearch.request(
        "PUT",
        f"{ROLE_ENDPOINT}/{role_name}",
        {**permissions, **action_groups},
    )
    # enable this role
    logger.debug(put_role_resp)
    if put_role_resp.get("status") != "OK":
        raise OpenSearchUserMgmtError()
    return put_role_resp


def remove_role(opensearch: OpenSearchDistribution, role_name: str) -> Dict[str, Any]:
    """Remove the given role from opensearch distribution.

    Args:
        opensearch: Opensearch distribution object, used to send requests
        role_name: name of the role to be removed.

    Raises:
        OpenSearchUserMgmtError: If the request fails.

    Returns:
        Output of the request.
    """
    resp = opensearch.request("DELETE", f"{ROLE_ENDPOINT}/{role_name}")
    logger.debug(resp)
    # check if I have to disable roles before removal
    if resp.get("status") != "OK":
        raise OpenSearchUserMgmtError()
    return resp


def create_user(
    opensearch: OpenSearchDistribution,
    username: str,
    roles: List[str],  # TODO add default
    hashed_pwd: str,
) -> Dict[str, Any]:
    """Create or update user and assign the requested roles to the user.

    Args:
        opensearch: Opensearch distribution object, used to send requests
        username: name of the user to be created.
        roles: list of roles to be applied to the user. These must already exist.
        hashed_pwd: the hashed password for the user.

    Raises:
        OpenSearchUserMgmtError: If the request fails.

    Returns:
        Output of the request.
    """
    payload = {"hash": hashed_pwd}
    if roles:
        payload["opendistro_security_roles"] = roles

    put_user_resp = opensearch.request(
        "PUT",
        f"{USER_ENDPOINT}/{username}",
        payload,
    )
    logger.debug(put_user_resp)
    if put_user_resp.get("status") != "CREATED":
        raise OpenSearchUserMgmtError()
    return put_user_resp


def remove_user(opensearch: OpenSearchDistribution, username: str) -> Dict[str, Any]:
    """Remove the given user from opensearch distribution.

    Args:
        opensearch: Opensearch distribution object, used to send requests
        username: name of the user to be removed.

    Raises:
        OpenSearchUserMgmtError: If the request fails.

    Returns:
        Output of the request.
    """
    resp = opensearch.request("DELETE", f"{USER_ENDPOINT}/{username}/")
    logger.debug(resp)
    if resp.get("status") != "OK":
        raise OpenSearchUserMgmtError()
    return resp


def patch_user(opensearch, user: str, patches: List[Dict[str, any]]) -> Dict[str, Any]:
    """Applies patches to user.

    TODO docs and tests
    """
    patch_user_resp = opensearch.request(
        "PATCH",
        f"{USER_ENDPOINT}/{user}",
        patches,
    )
    logger.debug(patch_user_resp)
    if patch_user_resp.get("status") != "OK":
        raise OpenSearchUserMgmtError()
    return patch_user_resp
