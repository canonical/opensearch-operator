# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, call, patch

from charms.opensearch.v0.constants_charm import NodeLockRelationName
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.models import (
    App,
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
    PEER_CLUSTERS_MANAGER = (
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager"
    )
    OPENSEARCH_DISTRO = ""

    deployment_descriptions = {
        "ok": DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid="model-uuid", name="opensearch"),
            state=DeploymentState(value=State.ACTIVE),
        ),
        "ko": DeploymentDescription(
            config=PeerClusterConfig(cluster_name="logs", init_hold=True, roles=["ml"]),
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[Directive.WAIT_FOR_PEER_CLUSTER_RELATION],
            typ=DeploymentType.OTHER,
            app=App(model_uuid="model-uuid", name="opensearch"),
            state=DeploymentState(value=State.BLOCKED_CANNOT_START_WITH_ROLES, message="error"),
        ),
        "cm-only": DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=["cluster-manager"]),
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid="model-uuid", name="opensearch"),
            state=DeploymentState(value=State.ACTIVE),
        ),
        "data-only": DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=["data"]),
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[],
            typ=DeploymentType.OTHER,
            app=App(model_uuid="model-uuid", name="opensearch"),
            state=DeploymentState(value=State.ACTIVE),
        ),
    }

    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm

        for typ in ["ok", "ko"]:
            self.deployment_descriptions[typ].app = App(
                model_uuid=self.charm.model.uuid, name="opensearch"
            )

        self.opensearch = self.charm.opensearch
        self.opensearch.current = MagicMock()
        self.opensearch.current.return_value = Node(
            name="cm1",
            roles=["cluster_manager", "data"],
            ip="1.1.1.1",
            app=self.deployment_descriptions["ok"].app,
            unit_number=3,
        )
        self.opensearch.is_failed = MagicMock()
        self.opensearch.is_failed.return_value = False

        self.peers_data = self.charm.peers_data

        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.lock_fallback_rel_id = self.harness.add_relation(
            NodeLockRelationName, self.charm.app.name
        )

        self.OPENSEARCH_DISTRO = (
            f"{self.opensearch.__class__.__module__}.{self.opensearch.__class__.__name__}"
        )

        self.secret_store = self.charm.secrets

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
    @patch(f"{BASE_CHARM_CLASS}._put_or_update_internal_user_leader")
    def test_on_leader_elected(
        self, _put_or_update_internal_user_leader, _purge_users, deployment_desc
    ):
        """Test on leader elected event."""
        deployment_desc.return_value = self.deployment_descriptions["ok"]
        self.harness.set_leader(True)

        _purge_users.assert_called_once()
        _put_or_update_internal_user_leader.assert_has_calls(
            [call("admin"), call("kibanaserver")], any_order=True
        )
        self.assertTrue(isinstance(self.harness.model.unit.status, ActiveStatus))

        _purge_users.reset_mock()
        _put_or_update_internal_user_leader.reset_mock()

        self.peers_data.put(Scope.APP, "admin_user_initialized", True)
        self.charm.on.leader_elected.emit()
        _purge_users.assert_called_once()
        _put_or_update_internal_user_leader.assert_has_calls(
            [call("admin"), call("kibanaserver")], any_order=True
        )

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch(f"{BASE_CHARM_CLASS}._purge_users")
    @patch(f"{BASE_CHARM_CLASS}._put_or_update_internal_user_leader")
    def test_on_leader_elected_index_initialised(
        self, _put_or_update_internal_user_leader, _purge_users, deployment_desc
    ):
        # security_index_initialised
        self.peers_data.put(Scope.APP, "security_index_initialised", True)
        deployment_desc.return_value = self.deployment_descriptions["ok"]
        self.harness.set_leader(True)

        self.charm.on.leader_elected.emit()
        _put_or_update_internal_user_leader.assert_not_called()
        _purge_users.assert_not_called()

        # admin_user_initialized
        self.peers_data.delete(Scope.APP, "security_index_initialised")
        self.peers_data.put(Scope.APP, "admin_user_initialized", True)
        self.charm.on.leader_elected.emit()
        _put_or_update_internal_user_leader.assert_has_calls(
            [call("admin"), call("kibanaserver")], any_order=True
        )
        _purge_users.assert_called_once()

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(f"{BASE_CHARM_CLASS}._initialize_security_index")
    @patch(f"{BASE_LIB_PATH}.opensearch_distro.OpenSearchDistribution.is_node_up")
    def test_cluster_manager_only_no_security_initialization(
        self,
        deployment_desc,
        _initialize_security_index,
        is_node_up,
    ):
        """Test that security index is not initialized after starting the cluster manager"""
        deployment_desc.config.roles.return_value = ["cluster-manager"]
        deployment_desc.start.return_value = StartMode.WITH_PROVIDED_ROLES
        self.harness.set_leader(True)
        start_event = MagicMock()

        with patch(f"{self.BASE_CHARM_CLASS}._get_nodes") as _get_nodes:
            _get_nodes.side_effect = OpenSearchHttpError()
            self.charm._post_start_init(start_event)
            _initialize_security_index.assert_not_called()

    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS.is_fully_configured")
    @patch(f"{BASE_CHARM_CLASS}.is_admin_user_configured")
    @patch(f"{BASE_LIB_PATH}.opensearch_config.OpenSearchConfig.set_client_auth")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(f"{BASE_CHARM_CLASS}._start_opensearch_event")
    @patch(f"{BASE_CHARM_CLASS}._apply_peer_cm_directives_and_check_if_can_start")
    def test_data_role_only_on_start(
        self,
        is_fully_configured,
        is_admin_user_configured,
        set_client_auth,
        deployment_desc,
        _start_opensearch_event,
        _apply_peer_cm_directives_and_check_if_can_start,
    ):
        """Test start event for nodes that only have the `data` role."""
        with patch(f"{self.OPENSEARCH_DISTRO}.is_node_up") as is_node_up:
            is_node_up.return_value = False
            _apply_peer_cm_directives_and_check_if_can_start.return_value = True
            is_fully_configured.return_value = True
            is_admin_user_configured.return_value = True
            deployment_desc.typ.return_value = DeploymentType.OTHER
            deployment_desc.config.roles.return_value = ["data"]

            self.harness.set_leader(True)
            self.charm.on.start.emit()

            self.charm._start_opensearch_event.emit.assert_called_once()

    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS.is_fully_configured")
    @patch(f"{BASE_CHARM_CLASS}.is_admin_user_configured")
    @patch(f"{BASE_LIB_PATH}.opensearch_config.OpenSearchConfig.set_client_auth")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(f"{BASE_CHARM_CLASS}._start_opensearch_event")
    @patch(f"{BASE_CHARM_CLASS}._apply_peer_cm_directives_and_check_if_can_start")
    def test_failover_orchestrator_with_data_role_on_start(
        self,
        is_fully_configured,
        is_admin_user_configured,
        set_client_auth,
        deployment_desc,
        _start_opensearch_event,
        _apply_peer_cm_directives_and_check_if_can_start,
    ):
        """Test start event for failover orchestrator with `data` role."""
        with patch(f"{self.OPENSEARCH_DISTRO}.is_node_up") as is_node_up:
            is_node_up.return_value = False
            _apply_peer_cm_directives_and_check_if_can_start.return_value = True
            is_fully_configured.return_value = True
            is_admin_user_configured.return_value = True
            deployment_desc.typ.return_value = DeploymentType.FAILOVER_ORCHESTRATOR
            deployment_desc.config.roles.return_value = ["cluster-manager", "data"]

            self.harness.set_leader(True)
            self.charm.on.start.emit()

            self.charm._start_opensearch_event.emit.assert_called_once()

    @patch(f"{BASE_LIB_PATH}.opensearch_locking.OpenSearchNodeLock.acquired")
    @patch(f"{PEER_CLUSTERS_MANAGER}.validate_roles")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(f"{PEER_CLUSTERS_MANAGER}.can_start")
    @patch(f"{BASE_CHARM_CLASS}.is_admin_user_configured")
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS.is_fully_configured")
    @patch(f"{BASE_LIB_PATH}.opensearch_config.OpenSearchConfig.set_client_auth")
    @patch(f"{BASE_CHARM_CLASS}._get_nodes")
    @patch(f"{BASE_CHARM_CLASS}._set_node_conf")
    @patch(f"{BASE_CHARM_CLASS}._can_service_start")
    @patch(f"{BASE_CHARM_CLASS}._initialize_security_index")
    @patch(f"{BASE_CHARM_CLASS}._purge_users")
    @patch(f"{BASE_CHARM_CLASS}._put_or_update_internal_user_unit")
    @patch(f"{BASE_LIB_PATH}.opensearch_distro.OpenSearchDistribution.request")
    @patch(f"{BASE_CHARM_CLASS}._post_start_init")
    def test_on_start(
        self,
        _post_start_init,
        request,
        _put_or_update_internal_user_unit,
        _purge_users,
        _initialize_security_index,
        _can_service_start,
        _set_node_conf,
        _get_nodes,
        set_client_auth,
        is_fully_configured,
        is_admin_user_configured,
        can_start,
        deployment_desc,
        validate_roles,
        lock_acquired,
    ):
        """Test on start event."""
        with patch(f"{self.OPENSEARCH_DISTRO}.is_node_up") as is_node_up:
            # test when setup complete
            is_node_up.return_value = True
            self.peers_data.put(Scope.APP, "security_index_initialised", True)
            self.charm.on.start.emit()
            is_fully_configured.assert_not_called()
            is_admin_user_configured.assert_not_called()

            # test when setup not complete
            is_node_up.return_value = False
            self.peers_data.delete(Scope.APP, "security_index_initialised")
            is_fully_configured.return_value = False
            is_admin_user_configured.return_value = False
            self.charm.on.start.emit()
            set_client_auth.assert_not_called()

        # when _get_nodes fails
        _get_nodes.side_effect = OpenSearchHttpError()
        self.charm.on.start.emit()
        _set_node_conf.assert_not_called()

        _get_nodes.reset_mock()

        # _get_nodes succeeds
        is_fully_configured.return_value = True
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
            _set_node_conf.reset_mock()
            self.peers_data.delete(Scope.APP, "security_index_initialised")
            _can_service_start.return_value = True
            self.harness.set_leader(True)
            lock_acquired.return_value = True

            self.charm.on.start.emit()

            # peer cluster manager
            deployment_desc.return_value = self.deployment_descriptions["ok"]
            can_start.return_value = True

            _get_nodes.side_effect = None
            _get_nodes.assert_called()
            validate_roles.side_effect = None
            validate_roles.assert_called()
            _set_node_conf.assert_called()
            start.assert_called_once()
            _post_start_init.assert_called_once()

    @patch(f"{BASE_LIB_PATH}.opensearch_backups.OpenSearchBackup.is_backup_in_progress")
    @patch(f"{BASE_LIB_PATH}.opensearch_backups.OpenSearchBackup._is_restore_complete")
    @patch(f"{BASE_CHARM_CLASS}._stop_opensearch")
    @patch(f"{BASE_LIB_PATH}.opensearch_base_charm.cert_expiration_remaining_hours")
    @patch(
        f"{BASE_LIB_PATH}.opensearch_relation_provider.OpenSearchProvider.remove_lingering_relation_users_and_roles"
    )
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

    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS.store_admin_tls_secrets_if_applies")
    @patch(f"{BASE_CHARM_CLASS}.is_admin_user_configured")
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS.is_fully_configured")
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS.reload_tls_certificates")
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS.update_request_ca_bundle")
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS.remove_old_ca")
    def test_reload_tls_certs_without_restart(
        self,
        store_admin_tls_secrets_if_applies,
        is_admin_user_configured,
        is_fully_configured,
        reload_tls_certificates,
        update_request_ca_bundle,
        remove_old_ca,
    ):
        """Test that tls configuration set does not trigger restart."""
        cert = "cert_12345"
        event_mock = MagicMock(certificate=cert)
        self.charm._restart_opensearch_event = MagicMock()

        self.charm.on_tls_conf_set(event_mock, scope="app", cert_type="app-admin", renewal=True)
        is_admin_user_configured.return_value = True
        is_fully_configured.return_value = True

        store_admin_tls_secrets_if_applies.assert_called_once()
        reload_tls_certificates.assert_called_once()
        update_request_ca_bundle.assert_called_once()

        remove_old_ca.assert_called_once()
        self.charm._restart_opensearch_event.emit.assert_not_called()

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

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    def test_unit_name(self, deployment_desc):
        """Test current unit name."""
        deployment_desc.return_value = self.deployment_descriptions["ok"]

        app_short_id = deployment_desc().app.short_id
        self.assertEqual(self.charm.unit_name, f"{self.charm.app.name}-0.{app_short_id}")

    def test_unit_id(self):
        """Test retrieving the integer id pf a unit."""
        self.assertEqual(self.charm.unit_id, 0)
