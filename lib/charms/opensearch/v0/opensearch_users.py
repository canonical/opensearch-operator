# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch user helpers."""

import logging
from typing import Dict, List, Optional

from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution

logger = logging.getLogger(__name__)


def create_role(
    opensearch: OpenSearchDistribution,
    role_name: str,
    permissions: Dict = {},
    action_groups: Dict = {},
) -> None:
    """Creates a role with the given permissions.

    This method assumes the dicts provided are valid opensearch config. If not, we should probably
    raise an error of some kind.

    TODO unit test
    """
    permissions.update(action_groups)
    put_role_resp = opensearch.request(
        "PUT",
        f"/_plugins/_security/api/roles/{role_name}",
        permissions,
    )
    logger.debug(put_role_resp)
    assert put_role_resp.get("status") == "OK"


def remove_role(opensearch: OpenSearchDistribution, role: str):
    """Remove the given role from opensearch distribution.

    TODO unit test
    """
    resp = opensearch.request("DELETE", f"/_plugins/_security/api/roles/{role}")
    logger.debug(resp)
    assert resp.get("status") == "OK"


def create_user(
    opensearch: OpenSearchDistribution,
    username: str,
    roles: List[str],
    password: str,
    hosts: Optional[List[str]],
    with_cert: bool,
) -> None:
    """Create or update user and assign the requested roles to the user.

    TODO add unit test
    """
    put_user_resp = opensearch.request(
        "PUT",
        f"/_plugins/_security/api/internalusers/{username}",
        {
            "password": password,
            "opendistro_security_roles": roles,
        },
    )
    logger.debug(put_user_resp)

    if with_cert:
        payload = {
            "users": [username],
            "opendistro_security_roles": roles,
        }
        if hosts is not None:
            payload["hosts"] = hosts

        put_role_mapping_resp = opensearch.request(
            "PUT",
            "/_plugins/_security/api/rolesmapping/",
            payload,
        )

        logger.debug(put_role_mapping_resp)

    assert put_user_resp.get("status") == "CREATED"


def remove_user(opensearch: OpenSearchDistribution, username: str):
    """Remove the given user from opensearch distribution.

    TODO unit test
    """
    resp = opensearch.request("DELETE", f"/_plugins/_security/api/internalusers/{username}/")
    logger.debug(resp)
    assert resp.get("status") == "OK"


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
