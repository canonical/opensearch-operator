# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest

import pytest
from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.opensearch_data import Scope
from ops import JujuVersion
from ops.testing import Harness
from overrides import override
from parameterized import parameterized

from charm import OpenSearchOperatorCharm


class TestHelperDatabag(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        # self.peers_data = self.charm.peers_data
        self.secret_store = self.charm.peers_data

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_get_null_without_default(self, scope):
        """Test fetching non-existent keys from the databag."""
        self.assertIsNone(self.secret_store.get(scope, "missing-key"))

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_get_none_without_default(self, scope):
        """Test fetching non-existent keys from the databag."""
        self.secret_store.put(scope, "noneval", None)
        self.assertIsNone(self.secret_store.get(scope, "noneval"))

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_typed_put_get(self, scope):
        """Test putting and getting typed data in/from the relation data store."""
        self.secret_store.put(scope, "bool-true", True)
        self.assertTrue(self.secret_store.get(scope, "bool-true"))
        self.assertTrue(self.secret_store.get(scope, "bool-true", auto_casting=False), "True")

        self.secret_store.put(scope, "bool-false", False)
        self.assertFalse(self.secret_store.get(scope, "bool-false"))
        self.assertTrue(self.secret_store.get(scope, "bool-false", auto_casting=False), "False")

        self.secret_store.put(scope, "int", 18)
        self.assertEqual(self.secret_store.get(scope, "int"), 18)
        self.assertEqual(self.secret_store.get(scope, "int", auto_casting=False), "18")

        self.secret_store.put(scope, "float", 2.6)
        self.assertEqual(self.secret_store.get(scope, "float"), 2.6)
        self.assertEqual(self.secret_store.get(scope, "float", auto_casting=False), "2.6")

        self.secret_store.put(scope, "str", "str-val")
        self.assertEqual(self.secret_store.get(scope, "str"), "str-val")
        self.assertEqual(self.secret_store.get(scope, "str", auto_casting=False), "str-val")

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_data_has(self, scope):
        """Test checking on the existence of a key."""
        self.secret_store.put(scope, "key1", "val1")
        self.assertTrue(self.secret_store.has(scope, "key1"))
        self.assertFalse(self.secret_store.has(scope, "key2"))

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_typed_get_with_default(self, scope):
        """Test putting and getting typed data in/from the relation data store."""
        self.assertTrue(self.secret_store.get(scope, "bool-missing-true", default=True))
        self.assertFalse(self.secret_store.get(scope, "bool-missing-false", default=False))

        self.assertEqual(self.secret_store.get(scope, "int-missing", 2), 2)
        self.assertEqual(self.secret_store.get(scope, "float-missing", default=2.5), 2.5)
        self.assertEqual(self.secret_store.get(scope, "str-missing", default="str"), "str")

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_put_get_set_object_signature(self, scope):
        """Test putting and getting objects in/from the secret store."""
        self.secret_store.put_object(scope, "key-obj", {"name1": "val1"})
        self.secret_store.put_object(scope, "key-obj", {"name2": "val2"})
        self.assertDictEqual(self.secret_store.get_object(scope, "key-obj"), {"name2": "val2"})

        self.secret_store.put_object(scope, "key-obj", {"name3": "val3"}, merge=True)
        self.assertDictEqual(
            self.secret_store.get_object(scope, "key-obj"), {"name2": "val2", "name3": "val3"}
        )

        self.secret_store.put_object(
            scope, "key-obj", {"name3": "redefined", "name4": "val4"}, merge=True
        )
        self.assertDictEqual(
            self.secret_store.get_object(scope, "key-obj"),
            {"name2": "val2", "name3": "redefined", "name4": "val4"},
        )

        self.secret_store.put_object(
            scope, "key-obj", {"name3": None, "name4": "val4"}, merge=True
        )
        secret = self.secret_store.get_object(scope, "key-obj")
        self.assertIsNone(secret.get("name3"))

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_put_get_set_object_implementation_specific_behavior(self, scope):
        """Test putting and getting objects in/from the secret store."""
        self.secret_store.put_object(scope, "key-obj", {"name1": "val1"}, merge=True)
        self.secret_store.put_object(
            scope, "key-obj", {"name1": None, "name2": "val2"}, merge=True
        )
        self.assertDictEqual(
            self.secret_store.get_object(scope, "key-obj"), {"name1": None, "name2": "val2"}
        )

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_delete(self, scope):
        """Test delete key."""
        self.secret_store.delete(scope, "nonexistent")
        self.assertIsNone(self.secret_store.get(scope, "nonexistent"))

        self.secret_store.put(scope, "key1", "val1")
        self.secret_store.delete(scope, "key1")
        self.assertIsNone(self.secret_store.get(scope, "key1"))

        self.secret_store.put_object(scope, "key-obj", {"key1": "val1", "key2": "val2"})
        self.secret_store.delete(scope, "key-obj")
        self.assertFalse(self.secret_store.has(scope, "key-obj"))
        self.assertIsNone(self.secret_store.get(scope, "key-obj"))

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_nullify_value(self, scope):
        """Test definging a key as `None`."""
        self.secret_store.put(scope, "key1", "val1")
        self.secret_store.put(scope, "key1", None)
        self.assertFalse(self.secret_store.has(scope, "key1"))

    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_nullify_obj(self, scope):
        """Test iteratively filling up an object with `None` values."""
        self.secret_store.put_object(scope, "key-obj", {"key1": "val1", "key2": "val2"})
        self.secret_store.put_object(scope, "key-obj", {"key1": None, "key2": "val2"}, merge=True)
        self.secret_store.put_object(scope, "key-obj", {"key2": None}, merge=True)
        self.assertTrue(self.secret_store.has(scope, "key-obj"))
        secret = self.secret_store.get_object(scope, "key-obj")
        self.assertIsNone(secret.get("key1"))
        self.assertIsNone(secret.get("key2"))


@pytest.mark.usefixtures("only_with_juju_secrets")
class TestHelperSecrets(TestHelperDatabag):
    """Ensuring that secrets interfaces and expected behavior are preserved.

    Additionally the class also highlights the difference introdced in SecretsDataStore
    """

    def setUp(self) -> None:
        super().setUp()
        self.secret_store = self.charm.secrets

    def test_implements_secrets(self):
        """Property determining whether secerts are available."""
        self.assertEqual(
            self.secret_store.implements_secrets, JujuVersion.from_environ().has_secrets
        )

    @override
    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_put_get_set_object_implementation_specific_behavior(self, scope):
        """Test putting and getting objects in/from the secret store."""
        self.secret_store.put_object(scope, "key-obj", {"name1": "val1"}, merge=True)
        self.secret_store.put_object(
            scope, "key-obj", {"name1": None, "name2": "val2"}, merge=True
        )
        self.assertDictEqual(self.secret_store.get_object(scope, "key-obj"), {"name2": "val2"})

    @override
    @parameterized.expand([(Scope.APP), (Scope.UNIT)])
    def test_nullify_obj(self, scope):
        """Test iteratively filling up an object with `None` values."""
        self.secret_store.put_object(scope, "key-obj", {"key1": "val1", "key2": "val2"})
        self.secret_store.put_object(scope, "key-obj", {"key1": None, "key2": "val2"}, merge=True)
        self.secret_store.put_object(scope, "key-obj", {"key2": None}, merge=True)
        self.assertFalse(self.secret_store.has(scope, "key-obj"))
