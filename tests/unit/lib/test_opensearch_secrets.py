# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import MagicMock, patch

import charms.opensearch.v0.opensearch_locking as opensearch_locking
from charms.opensearch.v0.constants_charm import (
    ClientRelationName,
    KibanaserverUser,
    PeerRelationName,
)
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import JujuVersion
from ops.testing import Harness
from overrides import override
from parameterized import parameterized
from unit.lib.test_opensearch_internal_data import TestOpenSearchInternalData

from charm import OpenSearchOperatorCharm


class JujuVersionMock:
    def has_secrets(self):
        return True


class TestOpenSearchSecrets(TestOpenSearchInternalData):
    """Ensuring that secrets interfaces and expected behavior are preserved.

    Additionally, the class also highlights the difference introduced in SecretsDataStore
    """

    def setUp(self):
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        # self.charm._on_leader_elected = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.begin()

        self.charm = self.harness.charm
        self.app = self.charm.app
        self.unit = self.charm.unit
        self.secrets = self.charm.secrets
        self.store = self.charm.secrets

        JujuVersion.from_environ = MagicMock(return_value=JujuVersionMock())

        self.peers_rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.lock_fallback_rel_id = self.harness.add_relation(
            opensearch_locking._PeerRelationLock._ENDPOINT_NAME, self.charm.app.name
        )
        self.client_rel_id = self.harness.add_relation(ClientRelationName, "application")
        self.harness.add_relation_unit(self.client_rel_id, "application/0")

    @patch("charm.OpenSearchOperatorCharm._put_admin_user")
    @patch("charm.OpenSearchOperatorCharm._put_kibanaserver_user")
    @patch(
        "charms.opensearch.v0.opensearch_relation_provider.OpenSearchProvider.update_dashboards_password"
    )
    @patch("charm.OpenSearchOperatorCharm.store_tls_resources")
    def test_on_secret_changed_app(
        self, mock_store_tls_resources, mock_update_dashboard_pw, _, __
    ):
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

        event.secret.label = f"opensearch:app:{KibanaserverUser}-password"
        self.secrets._on_secret_changed(event)
        mock_update_dashboard_pw.assert_called()

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

    def test_implements_secrets(self):
        """Property determining whether secrets are available."""
        self.assertEqual(self.store.implements_secrets, JujuVersion.from_environ().has_secrets)

    @override
    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_put_get_set_object_implementation_specific_behavior(self, scope):
        """Test putting and getting objects in/from the secret store."""
        self.store.put_object(scope, "key-obj", {"name1": "val1"}, merge=True)
        self.store.put_object(scope, "key-obj", {"name1": None, "name2": "val2"}, merge=True)
        self.assertDictEqual(self.store.get_object(scope, "key-obj"), {"name2": "val2"})

    @override
    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_nullify_obj(self, scope):
        """Test iteratively filling up an object with `None` values."""
        self.store.put_object(scope, "key-obj", {"key1": "val1", "key2": "val2"})
        self.store.put_object(scope, "key-obj", {"key1": None, "key2": "val2"}, merge=True)
        self.store.put_object(scope, "key-obj", {"key2": None}, merge=True)
        self.assertFalse(self.store.has(scope, "key-obj"))

    def test_label_app(self):
        scope = Scope.APP
        label = self.store.label(scope, "key1")
        self.assertEqual(label, f"opensearch:{scope}:key1")
        self.assertEqual(
            self.store.breakdown_label(label),
            {"application_name": "opensearch", "scope": scope, "unit_id": None, "key": "key1"},
        )

    def test_label_unit(self):
        scope = Scope.UNIT
        label = self.store.label(scope, "key1")
        self.assertEqual(self.store.label(scope, "key1"), f"opensearch:{scope}:0:key1")
        self.assertEqual(
            self.store.breakdown_label(label),
            {"application_name": "opensearch", "scope": scope, "unit_id": 0, "key": "key1"},
        )

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_save_secret_id(self, scope):
        """Test putting and getting objects in/from the secret store."""
        self.store.put(scope, "key", "val1")
        secret_id = self.store._get_relation_data(scope)[self.store.label(scope, "key")]
        secret_content = self.charm.model.get_secret(id=secret_id).get_content()
        self.assertEqual(secret_content["key"], "val1")

        self.store.put_object(scope, "key-obj", {"name1": "val1"}, merge=True)
        secret_id2 = self.store._get_relation_data(scope)[self.store.label(scope, "key-obj")]
        secret_content = self.charm.model.get_secret(id=secret_id2).get_content()
        self.assertEqual(secret_content["name1"], "val1")

    def test_bad_label(self):
        with self.assertRaises(ValueError):
            self.store.breakdown_label("bla")

        with self.assertRaises(ValueError):
            self.store.breakdown_label("bla-bla-bla")

        with self.assertRaises(ValueError):
            self.store.breakdown_label("bla:bla")

        with self.assertRaises(KeyError):
            self.store.breakdown_label("bla:bla:bla")

        with self.assertRaises(KeyError):
            self.store.breakdown_label("bla:bla:bla:bla")

    @override
    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_put_and_get_complex_obj(self, scope):
        return
