# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
import uuid
from unittest.mock import MagicMock

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.helper_networking import (
    get_host_ip,
    get_hostname_by_unit,
    is_reachable,
    unit_ip,
    units_ips,
)
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import patch_network_get


@patch_network_get("1.1.1.1")
class TestHelperNetworking(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)

    def test_get_host_ip(self):
        """Test host IP value."""
        self.assertEqual(get_host_ip(self.charm, PeerRelationName), "1.1.1.1")

    def test_get_hostname_by_unit(self):
        """Test the dns name returned."""
        self.assertEqual(
            get_hostname_by_unit(self.charm, self.charm.unit.name),
            f"{self.charm.app.name}-{self.charm.unit_id}.{self.charm.app.name}-endpoints",
        )

    def test_unit_ip(self):
        """Test the unit IP value."""
        self.assertEqual(unit_ip(self.charm, self.charm.unit, PeerRelationName), "1.1.1.1")

    def test_units_ips(self):
        """Test all units IPs."""
        self.harness.add_relation_unit(self.rel_id, f"{self.charm.app.name}/0")
        self.harness.add_relation_unit(self.rel_id, f"{self.charm.app.name}/1")
        self.harness.add_relation_unit(self.rel_id, f"{self.charm.app.name}/2")

        self.charm.opensearch_config = MagicMock()
        self.harness.update_relation_data(
            self.rel_id, f"{self.charm.app.name}/1", {"private-address": "2.2.2.2"}
        )
        self.harness.update_relation_data(
            self.rel_id, f"{self.charm.app.name}/2", {"private-address": "3.3.3.3"}
        )

        self.assertDictEqual(
            units_ips(self.charm, PeerRelationName),
            {"0": "1.1.1.1", "1": "2.2.2.2", "2": "3.3.3.3"},
        )

    def test_is_reachable(self):
        """Test if host is reachable."""
        self.assertTrue(is_reachable("google.com", 80))
        self.assertFalse(is_reachable(uuid.uuid4().hex, 80))
