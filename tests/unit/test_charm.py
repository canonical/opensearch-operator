# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.opensearch_base_charm import PEER
from charms.opensearch.v0.opensearch_distro import (
    OpenSearchHttpError,
    OpenSearchInstallError,
)
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestCharm(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _create_directories):
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PEER, self.charm.app.name)

        self.opensearch = self.charm.opensearch

    @patch("opensearch.OpenSearchTarball.install")
    def test_on_install(self, install):
        """Test the install event callback on success."""
        self.charm.on.install.emit()
        install.assert_called_once()

    @patch("opensearch.OpenSearchTarball.install")
    def test_on_install_error(self, install):
        """Test the install event callback on error."""
        install.side_effect = OpenSearchInstallError()
        self.charm.on.install.emit()
        self.assertTrue(isinstance(self.harness.model.unit.status, BlockedStatus))

    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def test_on_leader_elected(self, _initialize_admin_user):
        """Test on leader elected event."""
        self.harness.set_leader(True)
        self.charm.on.leader_elected.emit()
        _initialize_admin_user.assert_called_once()
        self.assertTrue(isinstance(self.harness.model.unit.status, ActiveStatus))

    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def test_on_leader_elected_index_initialised(self, _initialize_admin_user):
        # security_index_initialised
        self.charm.app_peers_data["security_index_initialised"] = "True"
        self.charm.on.leader_elected.emit()
        _initialize_admin_user.assert_not_called()

        # admin_user_initialized
        del self.charm.app_peers_data["security_index_initialised"]
        self.charm.app_peers_data["admin_user_initialized"] = "True"
        self.charm.on.leader_elected.emit()
        _initialize_admin_user.assert_not_called()

    @patch("opensearch.OpenSearchTarball.is_started")
    @patch("charm.OpenSearchOperatorCharm._is_tls_fully_configured")
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.set_client_auth")
    @patch("charm.OpenSearchOperatorCharm._get_nodes")
    @patch("charm.OpenSearchOperatorCharm._set_node_conf")
    @patch("charm.OpenSearchOperatorCharm._start_opensearch")
    @patch("charm.OpenSearchOperatorCharm._initialize_security_index")
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def test_on_start(
        self,
        _initialize_admin_user,
        _initialize_security_index,
        _start_opensearch,
        _set_node_conf,
        _get_nodes,
        set_client_auth,
        _is_tls_fully_configured,
        is_started,
    ):
        """Test on start event."""
        # test when setup complete
        is_started.return_value = True
        self.charm.app_peers_data["security_index_initialised"] = "True"
        self.charm.on.start.emit()
        _is_tls_fully_configured.assert_not_called()

        # test when setup not complete
        is_started.return_value = False
        del self.charm.app_peers_data["security_index_initialised"]
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
        _start_opensearch.return_value = False
        self.charm.on.start.emit()
        _get_nodes.assert_called()
        _set_node_conf.assert_called_once()
        _initialize_security_index.assert_not_called()

        # initialisation of the security index
        del self.charm.app_peers_data["security_index_initialised"]
        _start_opensearch.return_value = True
        self.harness.set_leader()
        self.charm.on.start.emit()
        self.assertEqual(self.charm.app_peers_data["security_index_initialised"], "True")
        _initialize_security_index.assert_called_once()

    @patch("charms.opensearch.v0.helper_security.cert_expiration_remaining_hours")
    @patch("opensearch.OpenSearchTarball.is_node_up")
    @patch("ops.model.Model.get_relation")
    @patch("opensearch.OpenSearchTarball.missing_sys_requirements")
    def test_on_update_status(
        self, missing_sys_requirements, get_relation, is_node_up, cert_expiration_remaining_hours
    ):
        """Test on update status."""
        # test missing sys requirements
        missing_sys_requirements.return_value = ["ulimit -n not set"]
        self.charm.on.update_status.emit()
        self.assertTrue(isinstance(self.harness.model.unit.status, BlockedStatus))

        # test when TLS relation is broken and cert is expiring soon
        get_relation.return_value = None
        is_node_up.return_value = True
        self.charm.unit_peers_data["certs_exp_checked_at"] = (
            datetime.now() - timedelta(hours=7)
        ).strftime("%Y-%m-%d %H:%M:%S")
        self.charm.secrets.put_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, {"cert": "transport"}
        )
        cert_expiration_remaining_hours.return_value = 24 * 3
        self.charm.on.update_status.emit()
        self.assertTrue(isinstance(self.harness.model.unit.status, BlockedStatus))
