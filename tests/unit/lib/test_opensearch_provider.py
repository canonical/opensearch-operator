# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import MagicMock, patch

from charms.opensearch.v0.constants_charm import ClientRelationName, PeerRelationName
from charms.opensearch.v0.opensearch_base_charm import SERVICE_MANAGER
from helpers import patch_network_get
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestOpenSearchProvider(unittest.TestCase):
    @patch_network_get(private_address="1.1.1.1")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _mkdirs):
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.app = self.charm.app
        self.unit = self.charm.unit
        self.client_relation = self.charm.client_relation

        self.peers_rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.service_rel_id = self.harness.add_relation(SERVICE_MANAGER, self.charm.app.name)

        # Define an opensearch_provider relation
        self.client_rel_id = self.harness.add_relation(ClientRelationName, "application")
        self.harness.add_relation_unit(self.client_rel_id, "application/0")

    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def test_on_database_requested(self, _initialize_admin_user):
        # TODO stub
        self.harness.set_leader()
        event = MagicMock()  # noqa: F841
        # self.client_relation._on_database_requested(event)
        # Verify we've called everything we should
