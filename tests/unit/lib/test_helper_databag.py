# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
from unittest.mock import patch

from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.opensearch_base_charm import PEER
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestHelperDatabag(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _create_directories) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PEER, self.charm.app.name)
        self.secret_store = self.charm.secrets
        self.peers_data = self.charm.peers_data

    def test_typed_put_get(self):
        """Test putting and getting typed data in/from the relation data store."""
        self.peers_data.put(Scope.APP, "bool-true", True)
        self.assertTrue(self.peers_data.get(Scope.APP, "bool-true"))
        self.assertTrue(self.peers_data.get(Scope.APP, "bool-true", auto_casting=False), "True")

        self.peers_data.put(Scope.APP, "bool-false", False)
        self.assertFalse(self.peers_data.get(Scope.APP, "bool-false"))
        self.assertTrue(self.peers_data.get(Scope.APP, "bool-false", auto_casting=False), "False")

        self.peers_data.put(Scope.UNIT, "int", 18)
        self.assertEqual(self.peers_data.get(Scope.UNIT, "int"), 18)
        self.assertEqual(self.peers_data.get(Scope.UNIT, "int", auto_casting=False), "18")

        self.peers_data.put(Scope.APP, "float", 2.6)
        self.assertEqual(self.peers_data.get(Scope.APP, "float"), 2.6)
        self.assertEqual(self.peers_data.get(Scope.APP, "float", auto_casting=False), "2.6")

        self.peers_data.put(Scope.APP, "str", "str-val")
        self.assertEqual(self.peers_data.get(Scope.APP, "str"), "str-val")
        self.assertEqual(self.peers_data.get(Scope.APP, "str", auto_casting=False), "str-val")

    def test_data_has(self):
        """Test checking on the existence of a key."""
        self.peers_data.put(Scope.APP, "key1", "val1")
        self.peers_data.put(Scope.UNIT, "key2", "val2")

        self.assertTrue(self.peers_data.has(Scope.APP, "key1"))
        self.assertTrue(self.peers_data.has(Scope.UNIT, "key2"))

        self.assertFalse(self.peers_data.has(Scope.APP, "key2"))
        self.assertFalse(self.peers_data.has(Scope.UNIT, "key1"))

    def test_get_all(self):
        """Test the full retrieval of the store data."""
        self.assertCountEqual(self.peers_data.all(Scope.APP), {})
        self.assertCountEqual(self.peers_data.all(Scope.UNIT), {})

        self.peers_data.put(Scope.APP, "str", "val-0")
        self.peers_data.put(Scope.APP, "int", 10)
        self.peers_data.put(Scope.UNIT, "str", "val-1")
        self.peers_data.put(Scope.UNIT, "float", 2.8)

        self.assertCountEqual(self.peers_data.all(Scope.APP), {"str": "val-0", "int": "10"})
        self.assertCountEqual(self.peers_data.all(Scope.UNIT), {"str": "val-1", "float": "2.8"})

    def test_typed_get_with_default(self):
        """Test putting and getting typed data in/from the relation data store."""
        self.assertTrue(self.peers_data.get(Scope.APP, "bool-missing-true", default=True))
        self.assertFalse(self.peers_data.get(Scope.APP, "bool-missing-false", default=False))

        self.assertEqual(self.peers_data.get(Scope.APP, "int-missing", 2), 2)
        self.assertEqual(self.peers_data.get(Scope.UNIT, "float-missing", default=2.5), 2.5)
        self.assertEqual(self.peers_data.get(Scope.APP, "str-missing", default="str"), "str")

    def test_get_null_without_default(self):
        """Test fetching non-existent keys from the databag."""
        self.assertIsNone(self.peers_data.get(Scope.APP, "missing-key"))
        self.assertIsNone(self.peers_data.get(Scope.UNIT, "missing-key"))

    def test_put_get(self):
        """Test putting and getting data of simple type in/from the secret store."""
        self.secret_store.put(Scope.UNIT, "unit-key", "unit-val")
        self.secret_store.put(Scope.APP, "app-key", "app-val")

        self.assertEqual(self.secret_store.get(Scope.UNIT, "unit-key"), "unit-val")
        self.assertEqual(self.secret_store.get(Scope.APP, "app-key"), "app-val")

    def test_put_get_object(self):
        """Test putting and getting objects in/from the secret store."""
        self.secret_store.put_object(Scope.UNIT, "unit-key-obj", {"key": "val"})
        self.secret_store.put_object(Scope.APP, "app-key-obj", {"name": "val"})

        self.assertDictEqual(
            self.secret_store.get_object(Scope.UNIT, "unit-key-obj"), {"key": "val"}
        )
        self.assertDictEqual(
            self.secret_store.get_object(Scope.APP, "app-key-obj"), {"name": "val"}
        )

    def test_delete(self):
        """Test delete key."""
        self.secret_store.delete(Scope.UNIT, "nonexistent")
        self.secret_store.delete(Scope.UNIT, "unit-key")
        self.secret_store.delete(Scope.APP, "app-key")

        self.assertIsNone(self.secret_store.get(Scope.UNIT, "unit-key"))
        self.assertIsNone(self.secret_store.get(Scope.APP, "app-key"))
