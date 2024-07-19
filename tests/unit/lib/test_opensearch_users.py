# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the opensearch_users library."""

import unittest
from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest
from charms.opensearch.v0.constants_charm import ClientRelationName, OpenSearchUsers
from charms.opensearch.v0.opensearch_users import (
    OpenSearchUserManager,
    OpenSearchUserMgmtError,
)

from tests.helpers import patch_network_get


@patch_network_get("1.1.1.1")
class TestOpenSearchUserManager(unittest.TestCase):
    def setUp(self):
        self.charm = MagicMock()
        self.opensearch = self.charm.opensearch
        self.mgr = OpenSearchUserManager(self.charm)

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    def test_create_role(self, _):
        self.opensearch.request.return_value = {"status": "not ok"}
        permissions = {"perm1": "gimme_perms"}
        action_groups = {"ag1": "gimme_more_perms"}
        role_kwargs = {
            "role_name": "role_name",
            "permissions": permissions,
            "action_groups": action_groups,
        }
        request_args = (
            "PUT",
            "/_plugins/_security/api/roles/role_name",
        )
        payload = {**permissions, **action_groups}

        with pytest.raises(OpenSearchUserMgmtError):
            self.mgr.create_role(**role_kwargs)
        self.opensearch.request.assert_called_with(*request_args, payload=payload)

        self.opensearch.request.reset_mock()
        self.opensearch.request.return_value = {"status": "CREATED"}
        self.mgr.create_role(**role_kwargs)
        self.opensearch.request.assert_called_with(*request_args, payload=payload)

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    def test_remove_role(self, _):
        self.opensearch.request.return_value = {"status": "not ok"}
        role = "role_name"
        with pytest.raises(OpenSearchUserMgmtError):
            self.mgr.remove_role(role)
        request_args = ("DELETE", "/_plugins/_security/api/roles/role_name")
        self.opensearch.request.assert_called_with(*request_args)

        self.opensearch.request.reset_mock()
        self.opensearch.request.return_value = {"status": "OK"}
        self.mgr.remove_role(role)
        self.opensearch.request.assert_called_with(*request_args)

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    def test_create_user(self, _):
        self.opensearch.request.return_value = {"status": "not ok"}
        roles = ["my_cool_role", "my_terrible_role"]
        hash_pw = "pw"
        user_kwargs = {
            "user_name": "username",
            "roles": roles,
            "hashed_pwd": hash_pw,
        }

        with pytest.raises(OpenSearchUserMgmtError):
            self.mgr.create_user(**user_kwargs)
        request_args = (
            "PUT",
            "/_plugins/_security/api/internalusers/username",
        )
        payload = {"hash": hash_pw, "opendistro_security_roles": roles}
        self.opensearch.request.assert_called_with(*request_args, payload=payload)

        self.opensearch.request.reset_mock()
        self.opensearch.request.return_value = {"status": "CREATED"}
        self.mgr.create_user(**user_kwargs)
        self.opensearch.request.assert_called_with(*request_args, payload=payload)

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    def test_remove_user(self, _):
        self.opensearch.request.return_value = {"status": "not ok"}
        user_name = "username"
        with pytest.raises(OpenSearchUserMgmtError):
            self.mgr.remove_user(user_name)
        request_args = ("DELETE", "/_plugins/_security/api/internalusers/username")
        self.opensearch.request.assert_called_with(*request_args)

        self.opensearch.request.reset_mock()
        self.opensearch.request.return_value = {"status": "OK"}
        self.mgr.remove_user(user_name)
        self.opensearch.request.assert_called_with(*request_args)

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    def test_patch_user(self, _):
        self.opensearch.request.return_value = {"status": "not ok"}
        patches = [{"test patch": "yep, looks like a test."}]
        patch_args = ("username", patches)
        with pytest.raises(OpenSearchUserMgmtError):
            self.mgr.patch_user(*patch_args)
        request_args = ("PATCH", "/_plugins/_security/api/internalusers/username")
        self.opensearch.request.assert_called_with(*request_args, payload=patches)

        self.opensearch.request.reset_mock()
        self.opensearch.request.return_value = {"status": "OK"}
        self.mgr.patch_user(*patch_args)
        self.opensearch.request.assert_called_with(*request_args, payload=patches)

    def test_avoid_removing_non_charmed_users_and_roles(self):
        relation_mocker = namedtuple("relation_mocker", ["id"])

        self.mgr.get_users = MagicMock(
            return_value={
                "non_charmed_user_1": {
                    "username": "non_charmed_user_1",
                    "roles": ["admin", "other_role1"],
                    "full_name": "Do not erase me",
                    "email": "noreply",
                    "enabled": True,
                },
                "non_charmed_user_2": {
                    "username": "non_charmed_user_2",
                    "roles": ["admin", "other_role1"],
                    "full_name": "Do not erase me",
                    "email": "noreply",
                    "enabled": True,
                },
                f"{ClientRelationName}_1": {
                    "username": "relation1",
                    "roles": ["admin", "other_role1", f"{ClientRelationName}_test"],
                    "full_name": "Do not erase me",
                    "email": "noreply",
                    "enabled": True,
                },
                f"{ClientRelationName}_2": {
                    "username": "relation_do_not_exist_anymore",
                    "roles": ["admin", "other_role1", f"{ClientRelationName}_remove_pls"],
                    "full_name": "Erase me",
                    "email": "noreply",
                    "enabled": True,
                },
            }
            | {user: {} for user in OpenSearchUsers}
        )

        self.mgr.get_roles = MagicMock(
            return_value={
                "admin": {
                    "cluster": ["all"],
                    "indices": [
                        {
                            "names": ["index1", "index2"],
                            "privileges": ["all"],
                            "allow_restricted_indices": False,
                            "field_security": {
                                "grant": ["title", "body"],
                            },
                        }
                    ],
                    "applications": [],
                    "run_as": ["other_user"],
                    "metadata": {
                        "version": 1,
                    },
                    "transient_metadata": {
                        "enabled": True,
                    },
                },
                "other_role1": {
                    "cluster": ["all"],
                    "indices": [
                        {
                            "names": ["index1", "index2"],
                            "privileges": ["all"],
                            "allow_restricted_indices": False,
                            "field_security": {
                                "grant": ["title", "body"],
                            },
                        }
                    ],
                    "applications": [],
                    "run_as": ["other_user"],
                    "metadata": {
                        "version": 1,
                    },
                    "transient_metadata": {
                        "enabled": True,
                    },
                },
                f"{ClientRelationName}_test": {},
                f"{ClientRelationName}_remove_pls": {},
            }
        )

        self.charm.model.relations.get = MagicMock(return_value=[relation_mocker(1)])
        self.mgr.remove_role = MagicMock()
        self.mgr.remove_user = MagicMock()
        self.mgr.remove_users_and_roles()
        self.mgr.remove_user.assert_called_once_with(f"{ClientRelationName}_2")
        self.mgr.remove_role.assert_called_once_with(f"{ClientRelationName}_remove_pls")
