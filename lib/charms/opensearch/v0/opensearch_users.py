# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch user helpers.

TODO update tests
"""

import logging
from typing import Any, Dict, List

from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution

logger = logging.getLogger(__name__)


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
        f"/_plugins/_security/api/roles/{role_name}",
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
    resp = opensearch.request("DELETE", f"/_plugins/_security/api/roles/{role_name}")
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
        f"/_plugins/_security/api/internalusers/{username}",
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
    resp = opensearch.request("DELETE", f"/_plugins/_security/api/internalusers/{username}/")
    logger.debug(resp)
    if resp.get("status") != "OK":
        raise OpenSearchUserMgmtError()
    return resp


# def oversee_users(self, departed_relation_id: Optional[int], event):
#     """Oversees the users of the application.

#     Function manages user relations by removing, updated, and creating
#     users; and dropping databases when necessary.

#     Args:
#         departed_relation_id: When specified execution of functions
#             makes sure to exclude the users and databases and remove
#             them if necessary.
#         event: relation event.

#     When the function is executed in relation departed event, the departed
#     relation is still on the list of all relations. Therefore, for proper
#     work of the function, we need to exclude departed relation from the list.
#     """
#     with MongoDBConnection(self.charm.mongodb_config) as mongo:
#         database_users = mongo.get_users()
#         relation_users = self._get_users_from_relations(departed_relation_id)

#         for username in database_users - relation_users:
#             logger.info("Remove relation user: %s", username)
#             mongo.drop_user(username)

#         for username in relation_users - database_users:
#             config = self._get_config(username, None)
#             if config.database is None:
#                 # We need to wait for the moment when the provider library
#                 # set the database name into the relation.
#                 continue
#             logger.info("Create relation user: %s on %s", config.username, config.database)
#             mongo.create_user(config)
#             self._set_relation(config)

#         for username in relation_users & database_users:
#             config = self._get_config(username, None)
#             logger.info("Update relation user: %s on %s", config.username, config.database)
#             mongo.update_user(config)
#             logger.info("Updating relation data according to diff")
#             self._diff(event)

#         if not self.charm.model.config["auto-delete"]:
#             return

#         database_dbs = mongo.get_databases()
#         relation_dbs = self._get_databases_from_relations(departed_relation_id)
#         for database in database_dbs - relation_dbs:
#             logger.info("Drop database: %s", database)
#             mongo.drop_database(database)
