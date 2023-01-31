# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the opensearch_users library."""

import unittest
from unittest.mock import MagicMock

import pytest
from charms.opensearch.v0.opensearch_users import (
    OpenSearchUserMgmtError,
    create_role,
    create_user,
    remove_role,
    remove_user,
)

from tests.helpers import patch_network_get


@patch_network_get("1.1.1.1")
class TestOpenSearchUsers(unittest.TestCase):
    def test_create_role(self):
        opensearch = MagicMock()
        opensearch.request.return_value = {"status": "not ok"}
        permissions = {"perm1": "gimme_perms"}
        action_groups = {"ag1": "gimme_more_perms"}
        role_kwargs = {
            "opensearch": opensearch,
            "role_name": "role_name",
            "permissions": permissions,
            "action_groups": action_groups,
        }

        with pytest.raises(OpenSearchUserMgmtError):
            create_role(**role_kwargs)
        request_args = (
            "PUT",
            "/_plugins/_security/api/roles/role_name",
            {**permissions, **action_groups},
        )
        opensearch.request.assert_called_with(*request_args)

        opensearch.request.reset_mock()
        opensearch.request.return_value = {"status": "OK"}
        create_role(**role_kwargs)
        opensearch.request.assert_called_with(*request_args)

    def test_remove_role(self):
        opensearch = MagicMock()
        opensearch.request.return_value = {"status": "not ok"}
        role_args = (opensearch, "role_name")
        with pytest.raises(OpenSearchUserMgmtError):
            remove_role(*role_args)
        request_args = ("DELETE", "/_plugins/_security/api/roles/role_name")
        opensearch.request.assert_called_with(*request_args)

        opensearch.request.reset_mock()
        opensearch.request.return_value = {"status": "OK"}
        remove_role(*role_args)
        opensearch.request.assert_called_with(*request_args)

    def test_create_user(self):
        opensearch = MagicMock()
        opensearch.request.return_value = {"status": "not ok"}
        roles = ["my_cool_role", "my_terrible_role"]
        hash_pw = "pw"
        user_kwargs = {
            "opensearch": opensearch,
            "username": "username",
            "roles": roles,
            "hashed_pwd": hash_pw,
        }

        with pytest.raises(OpenSearchUserMgmtError):
            create_user(**user_kwargs)
        request_args = (
            "PUT",
            "/_plugins/_security/api/internalusers/username",
            {"hash": hash_pw, "opendistro_security_roles": roles},
        )
        opensearch.request.assert_called_with(*request_args)

        opensearch.request.reset_mock()
        opensearch.request.return_value = {"status": "CREATED"}
        create_user(**user_kwargs)
        opensearch.request.assert_called_with(*request_args)

    def test_remove_user(self):
        opensearch = MagicMock()
        opensearch.request.return_value = {"status": "not ok"}
        user_args = (opensearch, "username")
        with pytest.raises(OpenSearchUserMgmtError):
            remove_user(*user_args)
        request_args = ("DELETE", "/_plugins/_security/api/internalusers/username/")
        opensearch.request.assert_called_with(*request_args)

        opensearch.request.reset_mock()
        opensearch.request.return_value = {"status": "OK"}
        remove_user(*user_args)
        opensearch.request.assert_called_with(*request_args)
