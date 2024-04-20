# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import charms.opensearch.v0.opensearch_locking as opensearch_locking
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.models import (
    DeploymentDescription,
    DeploymentState,
    DeploymentType,
    Directive,
    Node,
    PeerClusterConfig,
    StartMode,
    State,
)
from charms.opensearch.v0.opensearch_base_charm import PeerRelationName
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchHttpError,
    OpenSearchInstallError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import patch_network_get


@patch_network_get("1.1.1.1")
@patch.dict("os.environ", {"JUJU_CONTEXT_ID": "foo"})
class TestOpenSearchBaseCharm(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"
    BASE_CHARM_CLASS = f"{BASE_LIB_PATH}.opensearch_base_charm.OpenSearchBaseCharm"
    OPENSEARCH_DISTRO = ""

    deployment_descriptions = {
        "ok": DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app="opensearch",
            state=DeploymentState(value=State.ACTIVE),
        ),
        "ko": DeploymentDescription(
            config=PeerClusterConfig(cluster_name="logs", init_hold=True, roles=["ml"]),
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[Directive.WAIT_FOR_PEER_CLUSTER_RELATION],
            typ=DeploymentType.OTHER,
            app="opensearch",
            state=DeploymentState(value=State.BLOCKED_CANNOT_START_WITH_ROLES, message="error"),
        ),
    }

    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.opensearch = self.charm.opensearch
        self.opensearch.current = MagicMock()
        self.opensearch.current.return_value = Node(
            name="cm1",
            roles=["cluster_manager", "data"],
            ip="1.1.1.1",
            app_name="opensearch-ff2z",
            unit_number=3,
        )
        self.opensearch.is_failed = MagicMock()
        self.opensearch.is_failed.return_value = False

        self.peers_data = self.charm.peers_data

        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.lock_fallback_rel_id = self.harness.add_relation(
            opensearch_locking._PeerRelationLock._ENDPOINT_NAME, self.charm.app.name
        )

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

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch(f"{BASE_CHARM_CLASS}._purge_users")
    @patch(f"{BASE_CHARM_CLASS}._put_admin_user")
    def test_on_leader_elected(self, _put_admin_user, _purge_users, deployment_desc):
        """Test on leader elected event."""
        deployment_desc.return_value = self.deployment_descriptions["ok"]
        self.harness.set_leader(True)

        _purge_users.assert_called_once()
        _put_admin_user.assert_called_once()
        self.assertTrue(isinstance(self.harness.model.unit.status, ActiveStatus))

        _purge_users.reset_mock()
        _put_admin_user.reset_mock()

        self.peers_data.put(Scope.APP, "admin_user_initialized", True)
        self.charm.on.leader_elected.emit()
        _purge_users.assert_called_once()
        _put_admin_user.assert_called_once()

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch(f"{BASE_CHARM_CLASS}._purge_users")
    @patch(f"{BASE_CHARM_CLASS}._put_admin_user")
    def test_on_leader_elected_index_initialised(
        self, _put_admin_user, _purge_users, deployment_desc
    ):
        # security_index_initialised
        self.peers_data.put(Scope.APP, "security_index_initialised", True)
        deployment_desc.return_value = self.deployment_descriptions["ok"]
        self.harness.set_leader(True)

        self.charm.on.leader_elected.emit()
        _put_admin_user.assert_not_called()
        _purge_users.assert_not_called()

        # admin_user_initialized
        self.peers_data.delete(Scope.APP, "security_index_initialised")
        self.peers_data.put(Scope.APP, "admin_user_initialized", True)
        self.charm.on.leader_elected.emit()
        _put_admin_user.assert_called_once()
        _purge_users.assert_called_once()

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.validate_roles"
    )
    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch(f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.can_start")
    @patch(f"{BASE_CHARM_CLASS}.is_admin_user_configured")
    @patch(f"{BASE_CHARM_CLASS}.is_tls_fully_configured")
    @patch(f"{BASE_LIB_PATH}.opensearch_config.OpenSearchConfig.set_client_auth")
    @patch(f"{BASE_CHARM_CLASS}._get_nodes")
    @patch(f"{BASE_CHARM_CLASS}._set_node_conf")
    @patch(f"{BASE_CHARM_CLASS}._can_service_start")
    @patch(f"{BASE_CHARM_CLASS}._initialize_security_index")
    @patch(f"{BASE_CHARM_CLASS}._purge_users")
    @patch(f"{BASE_CHARM_CLASS}._put_admin_user")
    @patch(f"{BASE_LIB_PATH}.opensearch_distro.OpenSearchDistribution.request")
    def test_on_start(
        self,
        request,
        _put_admin_user,
        _purge_users,
        _initialize_security_index,
        _can_service_start,
        _set_node_conf,
        _get_nodes,
        set_client_auth,
        is_tls_fully_configured,
        is_admin_user_configured,
        can_start,
        deployment_desc,
        validate_roles,
    ):
        """Test on start event."""
        with patch(f"{self.OPENSEARCH_DISTRO}.is_node_up") as is_node_up:
            # test when setup complete
            is_node_up.return_value = True
            self.peers_data.put(Scope.APP, "security_index_initialised", True)
            self.charm.on.start.emit()
            is_tls_fully_configured.assert_not_called()
            is_admin_user_configured.assert_not_called()

            # test when setup not complete
            is_node_up.return_value = False
            self.peers_data.delete(Scope.APP, "security_index_initialised")
            is_tls_fully_configured.return_value = False
            is_admin_user_configured.return_value = False
            self.charm.on.start.emit()
            set_client_auth.assert_not_called()

        # when _get_nodes fails
        _get_nodes.side_effect = OpenSearchHttpError()
        self.charm.on.start.emit()
        _set_node_conf.assert_not_called()

        _get_nodes.reset_mock()

        # _get_nodes succeeds
        is_tls_fully_configured.return_value = True
        is_admin_user_configured.return_value = True
        _get_nodes.side_effect = None
        _can_service_start.return_value = False
        self.charm.on.start.emit()
        _get_nodes.assert_called_once()
        _set_node_conf.assert_not_called()
        _initialize_security_index.assert_not_called()

        with patch(f"{self.OPENSEARCH_DISTRO}.start") as start:
            # initialisation of the security index
            _get_nodes.reset_mock()
            self.peers_data.delete(Scope.APP, "security_index_initialised")
            _can_service_start.return_value = True
            self.harness.set_leader(True)
            self.charm.on.start.emit()

            # peer cluster manager
            deployment_desc.return_value = self.deployment_descriptions["ok"]
            can_start.return_value = True
            _get_nodes.assert_called()
            validate_roles.side_effect = None
            start.assert_called_once()
            _set_node_conf.assert_called()
            _initialize_security_index.assert_called_once()
            self.assertTrue(self.peers_data.get(Scope.APP, "security_index_initialised"))

    @patch(f"{BASE_LIB_PATH}.opensearch_backups.OpenSearchBackup.is_backup_in_progress")
    @patch(f"{BASE_LIB_PATH}.opensearch_backups.OpenSearchBackup._is_restore_complete")
    @patch(f"{BASE_CHARM_CLASS}._stop_opensearch")
    @patch(f"{BASE_LIB_PATH}.opensearch_base_charm.cert_expiration_remaining_hours")
    @patch(f"{BASE_LIB_PATH}.opensearch_users.OpenSearchUserManager.remove_users_and_roles")
    def test_on_update_status(self, _, cert_expiration_remaining_hours, _stop_opensearch, __, ___):
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
        self.assertIsNone(self.peers_data.get(Scope.APP, "app-key"))

        self.peers_data.put(Scope.APP, "app-key", "app-val")
        self.assertEqual(self.peers_data.get(Scope.APP, "app-key"), "app-val")

    def test_unit_peers_data(self):
        """Test getting data from the unit relation data bag."""
        self.assertIsNone(self.peers_data.get(Scope.UNIT, "unit-key"))

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
