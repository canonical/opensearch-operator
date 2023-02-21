# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
from unittest.mock import patch

from charms.opensearch.v0.helper_charm import Status
from charms.opensearch.v0.opensearch_base_charm import PEER
from ops.model import BlockedStatus, MaintenanceStatus, WaitingStatus
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
        self.status = self.charm.status

    def test_clear_status(self):
        """Test clearing the charm status."""
        self.charm.unit.status = WaitingStatus("Status Message 1")
        self.status.clear("Status Message 1", pattern=Status.CheckPattern.Equal)
        self.assertEqual(self.charm.unit.status.name, "active")

        self.charm.unit.status = WaitingStatus("Status Message 2")
        self.status.clear("Stat", pattern=Status.CheckPattern.Start)
        self.assertEqual(self.charm.unit.status.name, "active")

        self.charm.unit.status = MaintenanceStatus("Status Message 3")
        self.status.clear("ssage 3", pattern=Status.CheckPattern.End)
        self.assertEqual(self.charm.unit.status.name, "active")

        self.charm.unit.status = BlockedStatus("Status Message 4")
        self.status.clear("essage 4", pattern=Status.CheckPattern.Contain)
        self.assertEqual(self.charm.unit.status.name, "active")

        message_template = "Message {} filled by {}."
        self.charm.unit.status = BlockedStatus(message_template.format(5, "unit tests"))
        self.status.clear(message_template, pattern=Status.CheckPattern.Interpolated)
        self.assertEqual(self.charm.unit.status.name, "active")
