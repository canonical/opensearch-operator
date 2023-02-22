# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the opensearch_users library."""

import unittest
from unittest.mock import MagicMock, patch

import pytest
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
    def test_create_role(self, _request):
        self.opensearch.request.return_value = {"status": "not ok"}
        permissions = {"perm1": "gimme_perms"}
        action_groups = {"ag1": "gimme_more_perms"}
        role_kwargs = {
            "role_name": "role_name",
            "permissions": permissions,
            "action_groups": action_groups,
        }

        with pytest.raises(OpenSearchUserMgmtError):
            self.mgr.create_role(**role_kwargs)
        request_args = (
            "PUT",
            "/_plugins/_security/api/roles/role_name",
            {**permissions, **action_groups},
        )
        self.opensearch.request.assert_called_with(*request_args)

        self.opensearch.request.reset_mock()
        self.opensearch.request.return_value = {"status": "OK"}
        self.mgr.create_role(**role_kwargs)
        self.opensearch.request.assert_called_with(*request_args)

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    def test_remove_role(self, _request):
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
    def test_create_user(self, _request):
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
            {"hash": hash_pw, "opendistro_security_roles": roles},
        )
        self.opensearch.request.assert_called_with(*request_args)

        self.opensearch.request.reset_mock()
        self.opensearch.request.return_value = {"status": "CREATED"}
        self.mgr.create_user(**user_kwargs)
        self.opensearch.request.assert_called_with(*request_args)

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    def test_remove_user(self, _request):
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
    def test_patch_user(self, _request):
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
