# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
from unittest.mock import patch

import ops
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.opensearch_base_charm import PEER
from ops.testing import Harness

from charm import OpenSearchOperatorCharm

ops.testing.SIMULATE_CAN_CONNECT = True


class TestHelperDatabag(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _create_directories) -> None:
        self._peer_relation = PEER

        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(self._peer_relation, self.charm.app.name)
        self.secret_store = self.charm.secrets

    def test_put_get(self):
        """Test putting data of simple type in the secret store."""
        self.secret_store.put(Scope.UNIT, "unit-key", "unit-val")
        self.secret_store.put(Scope.APP, "app-key", "app-val")

        self.assertEqual(self.secret_store.get(Scope.UNIT, "unit-key"), "unit-val")
        self.assertEqual(self.secret_store.get(Scope.APP, "app-key"), "app-val")

    def test_put_get_object(self):
        """Test putting objects in the secret store."""
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
