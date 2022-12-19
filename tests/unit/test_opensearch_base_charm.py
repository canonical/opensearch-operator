# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.opensearch_base_charm import PEER, SERVICE_MANAGER
from charms.opensearch.v0.opensearch_distro import (
    OpenSearchHttpError,
    OpenSearchInstallError,
)
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import patch_network_get


@patch_network_get("1.1.1.1")
class TestOpenSearchBaseCharm(unittest.TestCase):

    BASE_LIB_PATH = "charms.opensearch.v0"
    BASE_CHARM_CLASS = f"{BASE_LIB_PATH}.opensearch_base_charm.OpenSearchBaseCharm"
    OPENSEARCH_DISTRO = ""

    @patch(f"{BASE_LIB_PATH}.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _create_directories) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.opensearch = self.charm.opensearch
        self.peers_data = self.charm.peers_data
        self.rel_id = self.harness.add_relation(PEER, self.charm.app.name)
        self.service_rel_id = self.harness.add_relation(SERVICE_MANAGER, self.charm.app.name)

        self.OPENSEARCH_DISTRO = (
            f"{self.opensearch.__class__.__module__}.{self.opensearch.__class__.__name__}"
        )

    def test_on_install(self):
        """Test the install event callback on success."""
        with patch(f"{self.OPENSEARCH_DISTRO}.install") as install:
            self.charm.on.install.emit()
            install.assert_called_once()

    def test_on_install_error(self):
        """Test the install event callback on error."""
        with patch(f"{self.OPENSEARCH_DISTRO}.install") as install:
            install.side_effect = OpenSearchInstallError()
            self.charm.on.install.emit()
            self.assertTrue(isinstance(self.harness.model.unit.status, BlockedStatus))

    @patch(f"{BASE_CHARM_CLASS}._initialize_admin_user")
    def test_on_leader_elected(self, _initialize_admin_user):
        """Test on leader elected event."""
        self.harness.set_leader(True)
        self.charm.on.leader_elected.emit()
        _initialize_admin_user.assert_called_once()
        self.assertTrue(isinstance(self.harness.model.unit.status, ActiveStatus))

    @patch(f"{BASE_CHARM_CLASS}._initialize_admin_user")
    def test_on_leader_elected_index_initialised(self, _initialize_admin_user):
        # security_index_initialised
        self.peers_data.put(Scope.APP, "security_index_initialised", True)
        self.harness.set_leader(True)
        self.charm.on.leader_elected.emit()
        _initialize_admin_user.assert_not_called()

        # admin_user_initialized
        self.peers_data.delete(Scope.APP, "security_index_initialised")
        self.peers_data.put(Scope.APP, "admin_user_initialized", True)
        self.charm.on.leader_elected.emit()
        _initialize_admin_user.assert_not_called()

    @patch(f"{BASE_CHARM_CLASS}._is_tls_fully_configured")
    @patch(f"{BASE_LIB_PATH}.opensearch_config.OpenSearchConfig.set_client_auth")
    @patch(f"{BASE_CHARM_CLASS}._get_nodes")
    @patch(f"{BASE_CHARM_CLASS}._set_node_conf")
    @patch(f"{BASE_CHARM_CLASS}._can_service_start")
    @patch(f"{BASE_CHARM_CLASS}._initialize_security_index")
    @patch(f"{BASE_CHARM_CLASS}._initialize_admin_user")
    def test_on_start(
        self,
        _initialize_admin_user,
        _initialize_security_index,
        _can_service_start,
        _set_node_conf,
        _get_nodes,
        set_client_auth,
        _is_tls_fully_configured,
    ):
        """Test on start event."""
        with patch(f"{self.OPENSEARCH_DISTRO}.is_started") as is_started:
            # test when setup complete
            is_started.return_value = True
            self.peers_data.put(Scope.APP, "security_index_initialised", True)
            self.charm.on.start.emit()
            _is_tls_fully_configured.assert_not_called()

            # test when setup not complete
            is_started.return_value = False
            self.peers_data.delete(Scope.APP, "security_index_initialised")
            _is_tls_fully_configured.return_value = False
            self.charm.on.start.emit()
            set_client_auth.assert_not_called()

        # when _get_nodes fails
        _get_nodes.side_effect = OpenSearchHttpError()
        self.charm.on.start.emit()
        _set_node_conf.assert_not_called()

        # _get_nodes succeeds
        _is_tls_fully_configured.return_value = True
        _get_nodes.side_effect = None
        _can_service_start.return_value = False
        self.charm.on.start.emit()
        _get_nodes.assert_not_called()
        _set_node_conf.assert_not_called()
        _initialize_security_index.assert_not_called()

        with patch(f"{self.OPENSEARCH_DISTRO}.start") as start:
            # initialisation of the security index
            self.peers_data.delete(Scope.APP, "security_index_initialised")
            _can_service_start.return_value = True
            self.harness.set_leader(True)
            self.charm.on.start.emit()
            _get_nodes.assert_called()
            _set_node_conf.assert_called()
            start.assert_called_once()
            self.assertTrue(self.peers_data.get(Scope.APP, "security_index_initialised"))
            _initialize_security_index.assert_called_once()

    @patch(f"{BASE_LIB_PATH}.helper_security.cert_expiration_remaining_hours")
    @patch("ops.model.Model.get_relation")
    def test_on_update_status(self, get_relation, cert_expiration_remaining_hours):
        """Test on update status."""
        with patch(
            f"{self.OPENSEARCH_DISTRO}.missing_sys_requirements"
        ) as missing_sys_requirements:
            # test missing sys requirements
            missing_sys_requirements.return_value = ["ulimit -n not set"]
            self.charm.on.update_status.emit()
            self.assertTrue(isinstance(self.harness.model.unit.status, BlockedStatus))

        with patch(f"{self.OPENSEARCH_DISTRO}.is_node_up") as is_node_up:
            # test when TLS relation is broken and cert is expiring soon
            get_relation.return_value = None
            is_node_up.return_value = True
            self.peers_data.put(
                Scope.UNIT,
                "certs_exp_checked_at",
                (datetime.now() - timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S"),
            )
            self.charm.secrets.put_object(
                Scope.UNIT, CertType.UNIT_TRANSPORT.val, {"cert": "transport"}
            )
            cert_expiration_remaining_hours.return_value = 24 * 3
            self.charm.on.update_status.emit()
            self.assertTrue(isinstance(self.harness.model.unit.status, BlockedStatus))

    def test_app_peers_data(self):
        """Test getting data from the app relation data bag."""
        self.assertEqual(self.peers_data.all(Scope.APP), {})

        self.peers_data.put(Scope.APP, "app-key", "app-val")
        self.assertEqual(self.peers_data.get(Scope.APP, "app-key"), "app-val")

    def test_unit_peers_data(self):
        """Test getting data from the unit relation data bag."""
        self.assertEqual(self.peers_data.all(Scope.UNIT), {})

        self.peers_data.put(Scope.UNIT, "unit-key", "unit-val")
        self.assertEqual(self.peers_data.get(Scope.UNIT, "unit-key"), "unit-val")

    @patch_network_get("1.1.1.1")
    def test_unit_ip(self):
        """Test current unit ip value."""
        self.assertEqual(self.charm.unit_ip, "1.1.1.1")

    def test_unit_name(self):
        """Test current unit name."""
        self.assertEqual(self.charm.unit_name, f"{self.charm.app.name}-0")

    def test_unit_id(self):
        """Test retrieving the integer id pf a unit."""
        self.assertEqual(self.charm.unit_id, 0)
