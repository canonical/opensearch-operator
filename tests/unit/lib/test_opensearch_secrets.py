# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import MagicMock, patch

from charms.opensearch.v0.constants_charm import (
    ClientRelationName,
    PeerRelationName,
    Scope,
)
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.opensearch_base_charm import SERVICE_MANAGER
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestOpenSearchSecrets(unittest.TestCase):
    """Testing OpenSearchSecrets component."""

    def setUp(self):
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.app = self.charm.app
        self.unit = self.charm.unit
        self.secrets = self.charm.secrets

        self.peers_rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.service_rel_id = self.harness.add_relation(SERVICE_MANAGER, self.charm.app.name)
        self.client_rel_id = self.harness.add_relation(ClientRelationName, "application")
        self.harness.add_relation_unit(self.client_rel_id, "application/0")

    @patch("charm.OpenSearchOperatorCharm._put_admin_user")
    @patch("charm.OpenSearchOperatorCharm.store_tls_resources")
    def test_on_secret_changed_app(self, mock_store_tls_resources, _):
        event = MagicMock()
        event.secret = MagicMock()

        self.harness.set_leader(True)

        event.secret.label = "opensearch:unit:0:key"
        self.secrets._on_secret_changed(event)
        mock_store_tls_resources.assert_not_called()

        event.secret.label = "opensearch:app:key"
        self.secrets._on_secret_changed(event)
        mock_store_tls_resources.assert_not_called()

        event.secret.label = f"opensearch:app:{CertType.APP_ADMIN.val}"
        self.secrets._on_secret_changed(event)
        mock_store_tls_resources.assert_not_called()

    @patch("charm.OpenSearchOperatorCharm.store_tls_resources")
    def test_on_secret_changed_unit(self, mock_store_tls_resources):
        event = MagicMock()
        event.secret = MagicMock()

        self.harness.set_leader(False)

        event.secret.label = "opensearch:app:key"
        self.secrets._on_secret_changed(event)
        mock_store_tls_resources.assert_not_called()

        event.secret.label = f"opensearch:unit:{self.charm.unit_id}:key"
        self.secrets._on_secret_changed(event)
        mock_store_tls_resources.assert_not_called()

        event.secret.label = f"opensearch:app:{CertType.APP_ADMIN.val}"
        self.secrets._on_secret_changed(event)
        mock_store_tls_resources.assert_called()
        mock_store_tls_resources.assert_called_with(CertType.APP_ADMIN, event.secret.get_content())

    def test_interface(self):
        """We want to make sure that the following public methods are always supported."""
        scope = Scope.APP
        self.secrets.put(scope, "key1", "val1")
        self.assertTrue(self.secrets.has(scope, "key1"))
        self.assertTrue(self.secrets.get(scope, "key1"), "val1")

        self.secrets.put_object(scope, "obj", {"key1": "val1"})
        self.assertTrue(self.secrets.has(scope, "obj"))
        self.assertTrue(self.secrets.get_object(scope, "obj"), {"key1": "val1"})
