# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import MagicMock, PropertyMock, patch

import charms.opensearch.v0.opensearch_locking as opensearch_locking
from charms.opensearch.v0.constants_charm import (
    ClientRelationName,
    KibanaserverRole,
    KibanaserverUser,
    PeerRelationName,
)
from charms.opensearch.v0.helper_security import generate_password
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_users import OpenSearchUserMgmtError
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import patch_network_get

DASHBOARDS_CHARM = "opensearch-dashboards"


@patch_network_get("1.1.1.1")
class TestOpenSearchProvider(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.app = self.charm.app
        self.unit = self.charm.unit
        self.opensearch_provider = self.charm.opensearch_provider
        self.secrets = self.charm.secrets

        self.peers_rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.lock_fallback_rel_id = self.harness.add_relation(
            opensearch_locking._PeerRelationLock._ENDPOINT_NAME, self.charm.app.name
        )

        # Define an opensearch_provider relation
        self.client_rel_id = self.harness.add_relation(ClientRelationName, "application")
        self.harness.add_relation_unit(self.client_rel_id, "application/0")

    @patch("charm.OpenSearchOperatorCharm._purge_users")
    @patch("charms.opensearch.v0.opensearch_distro.YamlConfigSetter.put")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up")
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
        return_value="1",
    )
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request",
        return_value={"status": "OK"},
    )
    @patch(
        "charms.opensearch.v0.opensearch_relation_provider.OpenSearchProvider.create_opensearch_users"
    )
    @patch(
        "charms.opensearch.v0.opensearch_relation_provider.generate_hashed_password",
        return_value=("hashed_pw", "password"),
    )
    @patch("charms.data_platform_libs.v0.data_interfaces.OpenSearchProvides.set_credentials")
    @patch("charms.data_platform_libs.v0.data_interfaces.OpenSearchProvides.set_version")
    def test_on_index_requested(
        self,
        _set_version,
        _set_credentials,
        _gen_pw,
        _create_users,
        _request,
        _opensearch_version,
        _is_node_up,
        _,
        __,
    ):
        event = MagicMock()
        event.relation.id = 1
        username = self.opensearch_provider._relation_username(event.relation)
        hashed_pw, password = _gen_pw.return_value

        self.harness.set_leader(False)
        self.opensearch_provider._on_index_requested(event)
        _is_node_up.assert_not_called()

        self.harness.set_leader(True)
        _is_node_up.return_value = False
        self.opensearch_provider._on_index_requested(event)
        event.defer.assert_called()

        _is_node_up.return_value = True
        event.extra_user_roles = "admin"
        event.index = "test_index"
        self.unit.status = ActiveStatus()
        self.opensearch_provider._on_index_requested(event)
        _create_users.assert_called_with(username, hashed_pw, event.index, event.extra_user_roles)
        _set_credentials.assert_called_with(event.relation.id, username, password)
        _set_version.assert_called_with(event.relation.id, _opensearch_version())
        self.assertNotIsInstance(self.unit.status, BlockedStatus)
        _set_credentials.reset_mock()
        _set_version.reset_mock()

        _create_users.side_effect = OpenSearchUserMgmtError()
        self.opensearch_provider._on_index_requested(event)
        self.assertIsInstance(self.unit.status, BlockedStatus)
        _set_credentials.assert_not_called()
        _set_version.assert_not_called()

    @patch("charm.OpenSearchOperatorCharm._purge_users")
    @patch("charms.opensearch.v0.opensearch_distro.YamlConfigSetter.put")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up")
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
        return_value="1",
    )
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request",
        return_value={"status": "OK"},
    )
    @patch(
        "charms.opensearch.v0.opensearch_relation_provider.OpenSearchProvider.create_opensearch_users"
    )
    @patch(
        "charms.opensearch.v0.opensearch_relation_provider.generate_hashed_password",
        return_value=("hashed_pw", "password"),
    )
    @patch("charms.data_platform_libs.v0.data_interfaces.OpenSearchProvides.set_credentials")
    @patch("charms.data_platform_libs.v0.data_interfaces.OpenSearchProvides.set_version")
    def test_on_index_requested_kibanaserver(
        self,
        _set_version,
        _set_credentials,
        _gen_pw,
        _create_users,
        _request,
        _opensearch_version,
        _is_node_up,
        _,
        __,
    ):
        event = MagicMock()
        event.relation.id = 1
        # username = self.opensearch_provider._relation_username(event.relation)
        username = "kibanaserver"
        # hashed_pw, password = _gen_pw.return_value

        self.harness.set_leader(False)
        self.opensearch_provider._on_index_requested(event)
        _is_node_up.assert_not_called()

        self.harness.set_leader(True)
        password = self.harness.charm.secrets.get(Scope.APP, self.secrets.password_key(username))
        _is_node_up.return_value = False
        self.opensearch_provider._on_index_requested(event)
        event.defer.assert_called()

        _is_node_up.return_value = True
        event.extra_user_roles = "kibana_server"
        event.index = ".opensearch-dashboards"
        self.unit.status = ActiveStatus()
        self.opensearch_provider._on_index_requested(event)
        _create_users.assert_not_called()
        _set_credentials.assert_called_with(event.relation.id, username, password)
        _set_version.assert_called_with(event.relation.id, _opensearch_version())
        self.assertNotIsInstance(self.unit.status, BlockedStatus)
        _set_credentials.reset_mock()
        _set_version.reset_mock()

    @patch("charms.opensearch.v0.opensearch_users.OpenSearchUserManager.create_user")
    @patch("charms.opensearch.v0.opensearch_users.OpenSearchUserManager.create_role")
    @patch("charms.opensearch.v0.opensearch_users.OpenSearchUserManager.patch_user")
    def test_create_opensearch_users(self, _patch_user, _create_role, _create_user):
        username = "username"
        hashed_pw = "my_cool_hash"
        extra_user_roles = "admin"
        index = "test_index"
        roles = [username]
        patches = [
            {"op": "replace", "path": "/opendistro_security_roles", "value": roles},
        ]

        self.opensearch_provider.create_opensearch_users(
            username, hashed_pw, index, extra_user_roles
        )
        # permissions and action groups are in extra_user_roles, so we create a new role.
        _create_role.assert_called_with(
            role_name=username,
            permissions=self.opensearch_provider.get_extra_user_role_permissions(
                extra_user_roles, index
            ),
        )
        _create_user.assert_called_with(username, roles, hashed_pw)
        _patch_user.assert_called_with(username, patches)

    def test_on_relation_departed(self):
        event = MagicMock()
        event.departing_unit.name = "some other unit"
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
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_relation_broken(self, _, __, _is_node_up, _remove_users, _unit_departing):
        event = MagicMock()
        event.relation.id = 0
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

    @patch("charms.data_platform_libs.v0.data_interfaces.OpenSearchProvides.set_endpoints")
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up",
        return_value=True,
    )
    @patch("charm.OpenSearchOperatorCharm._get_nodes")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_update_endpoints(self, _, __, _nodes, _is_node_up, _set_endpoints):
        self.harness.set_leader(True)
        node1 = MagicMock()
        node1.ip = "4.4.4.4"
        node2 = MagicMock()
        node2.ip = "5.5.5.5"
        _nodes.return_value = [node2, node1]  # out of order
        relation = MagicMock()
        relation.id = 1
        endpoints = [f"{node.ip}:{self.charm.opensearch.port}" for node in _nodes.return_value]
        self.opensearch_provider.update_endpoints(relation)
        _set_endpoints.assert_called_with(relation.id, ",".join(sorted(endpoints)))

    def add_dashboard_relation(self):
        opensearch_relation = self.harness.add_relation(
            "opensearch-client", "opensearch-dashboards"
        )
        self.harness.update_relation_data(
            opensearch_relation,
            f"{DASHBOARDS_CHARM}",
            {"requested-secrets": '["username", "password", "tls", "tls-ca", "uris"]'},
        )
        event = MagicMock()
        relation = MagicMock()
        relation.id = opensearch_relation
        event.extra_user_roles = "kibana_server"
        event.index = ".opensearch-dashboards"
        event.relation = relation
        self.opensearch_provider._on_index_requested(event)
        return opensearch_relation

    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request",
        return_value={"status": 200, "version": {"number": "2.12"}},
    )
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        return_value="2.12",
        new_callable=PropertyMock,
    )
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up",
        return_value=True,
    )
    @patch("charm.OpenSearchOperatorCharm._get_nodes")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_update_dashboards_password(
        self,
        _,
        __,
        _nodes,
        _is_node_up,
        ____,
        ______,
    ):
        self.harness.set_leader(True)
        node = MagicMock()
        node.ip = "4.4.4.4"
        _nodes.return_value = [node]

        # Assign Kibanaserver password
        username = KibanaserverUser
        orig_pwd = generate_password()
        pw_label_field = self.secrets.password_key(username)
        self.harness.charm.secrets.put(Scope.APP, pw_label_field, orig_pwd)

        # Create 2 relations
        opensearch_relation1 = self.add_dashboard_relation()
        opensearch_relation2 = self.add_dashboard_relation()

        self.harness.update_relation_data(
            opensearch_relation1, f"{DASHBOARDS_CHARM}", {"extra-user-roles": KibanaserverRole}
        )

        self.harness.update_relation_data(
            opensearch_relation2, f"{DASHBOARDS_CHARM}", {"extra-user-roles": KibanaserverRole}
        )

        # Check the relations have the correct Kibanaserver password
        peer_secret_label = "opensearch:app:kibanaserver-password"
        rel1_secret_label = f"opensearch-client.{opensearch_relation1}.user.secret"
        rel2_secret_label = f"opensearch-client.{opensearch_relation2}.user.secret"

        peer_secret = self.harness.model.get_secret(label=peer_secret_label)
        rel1_secret = self.harness.model.get_secret(label=rel1_secret_label)
        rel2_secret = self.harness.model.get_secret(label=rel2_secret_label)

        peer_password = peer_secret.get_content().get(pw_label_field)
        assert peer_password == orig_pwd
        assert peer_password == rel1_secret.get_content().get("password")
        assert peer_password == rel2_secret.get_content().get("password")

        # Change local Kibanaserver password
        new_pwd = generate_password()
        pw_label_field = self.secrets.password_key(username)
        self.harness.charm.secrets.put(Scope.APP, pw_label_field, new_pwd)

        # Normally a secret_changed event is supposed to be triggered
        # (Unittests may not do that for the leader...?)
        secret_event = MagicMock()
        secret_event.relation = self.peers_rel_id
        secret_event.secret = peer_secret
        self.charm.secrets._on_secret_changed(secret_event)

        # Check that password got changed on the Dashboard relations
        peer_secret = self.harness.model.get_secret(label=peer_secret_label)
        rel1_secret = self.harness.model.get_secret(label=rel1_secret_label)
        rel2_secret = self.harness.model.get_secret(label=rel2_secret_label)

        peer_password = peer_secret.peek_content().get(pw_label_field)
        assert peer_password == new_pwd
        assert peer_password == rel1_secret.peek_content().get("password")
        assert peer_password == rel2_secret.peek_content().get("password")
