# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
from unittest.mock import patch

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.models import (
    DeploymentDescription,
    DeploymentState,
    DeploymentType,
    PeerClusterConfig,
    StartMode,
    State,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.testing import Harness
from parameterized import parameterized

from charm import OpenSearchOperatorCharm


class TestOpenSearchInternalData(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"

    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.store = self.charm.peers_data

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_get_null_without_default(self, scope):
        """Test fetching non-existent keys from the databag."""
        self.assertIsNone(self.store.get(scope, "missing-key"))

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_get_none_without_default(self, scope):
        """Test fetching non-existent keys from the databag."""
        self.store.put(scope, "noneval", None)
        self.assertIsNone(self.store.get(scope, "noneval"))

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_typed_put_get(self, scope):
        """Test putting and getting typed data in/from the relation data store."""
        self.store.put(scope, "bool-true", True)
        self.assertTrue(self.store.get(scope, "bool-true"))
        self.assertTrue(self.store.get(scope, "bool-true", auto_casting=False), "True")

        self.store.put(scope, "bool-false", False)
        self.assertFalse(self.store.get(scope, "bool-false"))
        self.assertTrue(self.store.get(scope, "bool-false", auto_casting=False), "False")

        self.store.put(scope, "int", 18)
        self.assertEqual(self.store.get(scope, "int"), 18)
        self.assertEqual(self.store.get(scope, "int", auto_casting=False), "18")

        self.store.put(scope, "float", 2.6)
        self.assertEqual(self.store.get(scope, "float"), 2.6)
        self.assertEqual(self.store.get(scope, "float", auto_casting=False), "2.6")

        self.store.put(scope, "str", "str-val")
        self.assertEqual(self.store.get(scope, "str"), "str-val")
        self.assertEqual(self.store.get(scope, "str", auto_casting=False), "str-val")

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_data_has(self, scope):
        """Test checking on the existence of a key."""
        self.store.put(scope, "key1", "val1")
        self.assertTrue(self.store.has(scope, "key1"))
        self.assertFalse(self.store.has(scope, "key2"))

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_typed_get_with_default(self, scope):
        """Test putting and getting typed data in/from the relation data store."""
        self.assertTrue(self.store.get(scope, "bool-missing-true", default=True))
        self.assertFalse(self.store.get(scope, "bool-missing-false", default=False))

        self.assertEqual(self.store.get(scope, "int-missing", 2), 2)
        self.assertEqual(self.store.get(scope, "float-missing", default=2.5), 2.5)
        self.assertEqual(self.store.get(scope, "str-missing", default="str"), "str")

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_put_get_set_object_signature(self, scope):
        """Test putting and getting objects in/from the secret store."""
        self.store.put_object(scope, "key-obj", {"name1": "val1"})
        self.store.put_object(scope, "key-obj", {"name2": "val2"})
        self.assertDictEqual(self.store.get_object(scope, "key-obj"), {"name2": "val2"})

        self.store.put_object(scope, "key-obj", {"name3": "val3"}, merge=True)
        self.assertDictEqual(
            self.store.get_object(scope, "key-obj"), {"name2": "val2", "name3": "val3"}
        )

        self.store.put_object(
            scope, "key-obj", {"name3": "redefined", "name4": "val4"}, merge=True
        )
        self.assertDictEqual(
            self.store.get_object(scope, "key-obj"),
            {"name2": "val2", "name3": "redefined", "name4": "val4"},
        )

        self.store.put_object(scope, "key-obj", {"name3": None, "name4": "val4"}, merge=True)
        secret = self.store.get_object(scope, "key-obj")
        self.assertIsNone(secret.get("name3"))

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_put_get_set_object_implementation_specific_behavior(self, scope):
        """Test putting and getting objects in/from the secret store."""
        self.store.put_object(scope, "key-obj", {"name1": "val1"}, merge=True)
        self.store.put_object(scope, "key-obj", {"name1": None, "name2": "val2"}, merge=True)
        self.assertDictEqual(
            self.store.get_object(scope, "key-obj"), {"name1": None, "name2": "val2"}
        )

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_delete(self, scope):
        """Test delete key."""
        self.store.delete(scope, "nonexistent")
        self.assertIsNone(self.store.get(scope, "nonexistent"))

        self.store.put(scope, "key1", "val1")
        self.store.delete(scope, "key1")
        self.assertIsNone(self.store.get(scope, "key1"))

        self.store.put_object(scope, "key-obj", {"key1": "val1", "key2": "val2"})
        self.store.delete(scope, "key-obj")
        self.assertFalse(self.store.has(scope, "key-obj"))
        self.assertIsNone(self.store.get(scope, "key-obj"))

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_nullify_value(self, scope):
        """Test defining a key as `None`."""
        self.store.put(scope, "key1", "val1")
        self.store.put(scope, "key1", None)
        self.assertFalse(self.store.has(scope, "key1"))

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_nullify_obj(self, scope):
        """Test iteratively filling up an object with `None` values."""
        self.store.put_object(scope, "key-obj", {"key1": "val1", "key2": "val2"})
        self.store.put_object(scope, "key-obj", {"key1": None, "key2": "val2"}, merge=True)
        self.store.put_object(scope, "key-obj", {"key2": None}, merge=True)
        self.assertTrue(self.store.has(scope, "key-obj"))
        secret = self.store.get_object(scope, "key-obj")
        self.assertIsNone(secret.get("key1"))
        self.assertIsNone(secret.get("key2"))

    @parameterized.expand([Scope.APP, Scope.UNIT])
    def test_put_and_get_complex_obj(self, scope):
        """Test putting complex nested object."""
        with patch(f"{self.BASE_LIB_PATH}.models.datetime") as datetime:
            datetime.now.return_value.timestamp.return_value = 12345788.12
            deployment = DeploymentDescription(
                config=PeerClusterConfig(
                    cluster_name="logs", init_hold=False, roles=["cluster_manager", "data"]
                ),
                start=StartMode.WITH_PROVIDED_ROLES,
                pending_directives=[],
                app=self.charm.app.name,
                typ=DeploymentType.MAIN_ORCHESTRATOR,
                state=DeploymentState(value=State.ACTIVE),
            )
            self.store.put_object(scope, "deployment", deployment.to_dict())
            fetched_deployment = DeploymentDescription.from_dict(
                self.store.get_object(scope, "deployment")
            )
            self.assertEqual(deployment, fetched_deployment)
