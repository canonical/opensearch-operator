# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
from unittest.mock import patch

from charms.opensearch.v0.opensearch_base_charm import PEER
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import patch_network_get


class TestHelperDatabag(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _create_directories) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PEER, self.charm.app.name)

    def test_app_peers_data(self):
        """Test getting data from the app relation data bag."""
        self.assertEqual(self.charm.app_peers_data, {})

        self.charm.app_peers_data["app-key"] = "app-val"
        self.assertEqual(self.charm.app_peers_data["app-key"], "app-val")

    def test_unit_peers_data(self):
        """Test getting data from the unit relation data bag."""
        self.assertEqual(self.charm.unit_peers_data, {})

        self.charm.app_peers_data["unit-key"] = "unit-val"
        self.assertEqual(self.charm.app_peers_data["unit-key"], "unit-val")

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
