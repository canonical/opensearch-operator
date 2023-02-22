# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from unittest.mock import MagicMock, PropertyMock, patch

from charms.opensearch.v0.constants_charm import ClientRelationName, PeerRelationName
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.opensearch_base_charm import SERVICE_MANAGER
from charms.opensearch.v0.opensearch_users import OpenSearchUserMgmtError
from helpers import patch_network_get
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


@patch_network_get("1.1.1.1")
class TestOpenSearchProvider(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _mkdirs):
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.app = self.charm.app
        self.unit = self.charm.unit
        self.opensearch_provider = self.charm.opensearch_provider

        self.peers_rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.service_rel_id = self.harness.add_relation(SERVICE_MANAGER, self.charm.app.name)

        # Define an opensearch_provider relation
        self.client_rel_id = self.harness.add_relation(ClientRelationName, "application")
        self.harness.add_relation_unit(self.client_rel_id, "application/0")

    @patch("charm.OpenSearchOperatorCharm._purge_users")
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up")
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
        return_value="1",
    )
    @patch(
        "charms.opensearch.v0.opensearch_relation_provider.OpenSearchProvider.create_opensearch_users"
    )
    @patch(
        "charms.opensearch.v0.opensearch_relation_provider.generate_hashed_password",
        return_value=("hashed_pw", "password"),
    )
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseProvides.set_credentials")
    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseProvides.set_version")
    def test_on_database_requested(
        self,
        _set_version,
        _set_credentials,
        _gen_pw,
        _create_users,
        _opensearch_version,
        _is_node_up,
        _init_admin,
        _purge_users,
    ):
        event = MagicMock()
        event.relation.id = 1
        username = self.opensearch_provider._relation_username(event.relation)
        hashed_pw, password = _gen_pw.return_value

        self.harness.set_leader(False)
        self.opensearch_provider._on_database_requested(event)
        _is_node_up.assert_not_called()

        self.harness.set_leader(True)
        _is_node_up.return_value = False
        self.opensearch_provider._on_database_requested(event)
        event.defer.assert_called()

        _is_node_up.return_value = True
        event.extra_user_roles = None
        self.opensearch_provider._on_database_requested(event)
        self.assertIsInstance(self.unit.status, BlockedStatus)

        event.extra_user_roles = json.dumps({"roles": ["role"]})
        self.unit.status = ActiveStatus()
        self.opensearch_provider._on_database_requested(event)
        # no permissions or action groups in extra_user_roles, so we aren't creating a new role.
        _create_users.assert_called_with(username, hashed_pw, json.loads(event.extra_user_roles))
        _set_credentials.assert_called_with(event.relation.id, username, password)
        _set_version.assert_called_with(event.relation.id, _opensearch_version())
        self.assertNotIsInstance(self.unit.status, BlockedStatus)
        _set_credentials.reset_mock()
        _set_version.reset_mock()

        _create_users.side_effect = OpenSearchUserMgmtError()
        self.opensearch_provider._on_database_requested(event)
        self.assertIsInstance(self.unit.status, BlockedStatus)
        _set_credentials.assert_not_called()
        _set_version.assert_not_called()

    @patch("charms.opensearch.v0.opensearch_users.OpenSearchUserManager.create_user")
    @patch("charms.opensearch.v0.opensearch_users.OpenSearchUserManager.create_role")
    @patch("charms.opensearch.v0.opensearch_users.OpenSearchUserManager.patch_user")
    def test_create_opensearch_users(self, _patch_user, _create_role, _create_user):
        username = "username"
        hashed_pw = "my_cool_hash"
        roles = ["all_access"]
        access_control = {"roles": roles}
        patches = [{"op": "replace", "path": "/opendistro_security_roles", "value": roles}]

        self.opensearch_provider.create_opensearch_users(username, hashed_pw, access_control)
        # no permissions or action groups in extra_user_roles, so we aren't creating a new role.
        _create_role.assert_not_called()
        _create_user.assert_called_with(username, roles, hashed_pw)
        _patch_user.assert_called_with(username, patches)

        # Assert we can create a user with roles, permissions, and action groups
        access_control = {
            "roles": roles,
            "permissions": ["cluster:admin/ingest/pipeline/delete"],
            "action_groups": ["get"],
        }
        self.opensearch_provider.create_opensearch_users(username, hashed_pw, access_control)
        # permissions and action groups are in extra_user_roles, so we create a new role.
        _create_role.assert_called_with(
            role_name=username,
            permissions=access_control["permissions"],
            action_groups=access_control["action_groups"],
        )
        _create_user.assert_called_with(username, roles, hashed_pw)
        patches = [{"op": "replace", "path": "/opendistro_security_roles", "value": roles}]
        _patch_user.assert_called_with(username, patches)

    def test_on_relation_departed(self):
        event = MagicMock()
        event.departing_unit = None
        self.opensearch_provider._on_relation_departed(event)
        assert not self.charm.peers_data.get(
            Scope.UNIT, self.opensearch_provider._depart_flag(event.relation)
        )

        event.departing_unit = self.unit
        self.opensearch_provider._on_relation_departed(event)
        assert (
            self.charm.peers_data.get(
                Scope.UNIT, self.opensearch_provider._depart_flag(event.relation)
            )
            is True
        )

    @patch("charms.opensearch.v0.opensearch_relation_provider.OpenSearchProvider._unit_departing")
    @patch("charms.opensearch.v0.opensearch_users.OpenSearchUserManager.remove_users_and_roles")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up")
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_relation_broken(self, _, __, _is_node_up, _remove_users, _unit_departing):
        event = MagicMock()
        depart_flag = self.opensearch_provider._depart_flag(event.relation)

        self.harness.set_leader(False)
        _is_node_up.return_value = False
        self.opensearch_provider._on_relation_broken(event)
        _remove_users.assert_not_called()

        self.harness.set_leader(True)
        _is_node_up.return_value = True
        _unit_departing.return_value = True
        self.charm.peers_data.put(Scope.UNIT, depart_flag, "true")
        self.opensearch_provider._on_relation_broken(event)
        assert not self.charm.peers_data.get(Scope.UNIT, depart_flag)
        _remove_users.assert_not_called()

        _unit_departing.return_value = False
        self.opensearch_provider._on_relation_broken(event)
        assert not self.charm.peers_data.get(Scope.UNIT, depart_flag)
        _remove_users.assert_called_with(event.relation.id)

    @patch("charms.data_platform_libs.v0.data_interfaces.DatabaseProvides.set_endpoints")
    @patch(
        "charms.opensearch.v0.opensearch_relation_provider.units_ips",
        return_value={"1": "1.1.1.1", "2": "2.2.2.2"},
    )
    def test_update_endpoints(self, _ips, _set_endpoints):
        relation = MagicMock()
        relation.id = 1
        endpoints = [f"{ip}:{self.charm.opensearch.port}" for ip in _ips.return_value.values()]
        self.opensearch_provider.update_endpoints(relation)
        _set_endpoints.assert_called_with(relation.id, ",".join(endpoints))
