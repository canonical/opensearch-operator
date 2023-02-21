# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest
from unittest.mock import patch

from charms.opensearch.v0.helper_cluster import ClusterState, ClusterTopology, Node
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestHelperCluster(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _create_directories) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm

        self.opensearch = self.charm.opensearch

        self.base_roles = ["data", "ingest", "ml", "coordinating_only"]
        self.voting_only_roles = self.base_roles + ["voting_only"]
        self.cm_roles = self.base_roles + ["cluster_manager"]

        self.nodes_0 = []
        self.nodes_1 = [Node("cm1", self.cm_roles, "2.2.2.2")]
        self.nodes_2 = self.nodes_1 + [Node("voting1", self.voting_only_roles, "2.2.2.3")]
        self.nodes_3 = self.nodes_2 + [Node("cm2", self.cm_roles, "2.2.2.4")]
        self.nodes_4 = self.nodes_3 + [Node("data2", self.base_roles, "2.2.2.5")]
        self.nodes_5 = self.nodes_4 + [Node("cm3", self.cm_roles, "2.2.2.6")]

    def test_topology_roles_suggestion(self):
        """Test the suggestion of roles for a new node."""
        self.assertCountEqual(ClusterTopology.suggest_roles(self.nodes_0, 2), self.cm_roles)
        self.assertCountEqual(ClusterTopology.suggest_roles(self.nodes_1, 2), self.base_roles)
        self.assertCountEqual(ClusterTopology.suggest_roles(self.nodes_2, 3), self.cm_roles)
        self.assertCountEqual(ClusterTopology.suggest_roles(self.nodes_3, 4), self.base_roles)

    def test_topology_get_cluster_managers_ips(self):
        """Test correct retrieval of cm ips from a list of nodes."""
        self.assertCountEqual(
            ClusterTopology.get_cluster_managers_ips(self.nodes_4), ["2.2.2.2", "2.2.2.4"]
        )

    def test_topology_get_cluster_managers_names(self):
        """Test correct retrieval of cm ips from a list of nodes."""
        self.assertCountEqual(
            ClusterTopology.get_cluster_managers_names(self.nodes_4), ["cm1", "cm2"]
        )

    def test_topology_nodes_count_by_role(self):
        """Test correct mapping role / count of nodes with the role."""
        self.assertDictEqual(
            ClusterTopology.nodes_count_by_role(self.nodes_4),
            {
                "cluster_manager": 2,
                "voting_only": 1,
                "data": 4,
                "ml": 4,
                "coordinating_only": 4,
                "ingest": 4,
            },
        )

    @patch("charms.opensearch.v0.helper_cluster.ClusterState.shards")
    def test_state_busy_shards_by_unit(self, shards):
        """Test the busy shards filtering."""
        shards.return_value = [
            {"index": "index1", "state": "STARTED", "node": "opensearch-0"},
            {"index": "index1", "state": "INITIALIZING", "node": "opensearch-1"},
            {"index": "index2", "state": "STARTED", "node": "opensearch-0"},
            {"index": "index2", "state": "RELOCATING", "node": "opensearch-1"},
            {"index": "index3", "state": "STARTED", "node": "opensearch-0"},
            {"index": "index3", "state": "STARTED", "node": "opensearch-1"},
            {"index": "index4", "state": "STARTED", "node": "opensearch-2"},
            {"index": "index4", "state": "INITIALIZING", "node": "opensearch-2"},
        ]
        self.assertDictEqual(
            ClusterState.busy_shards_by_unit(self.opensearch),
            {"opensearch-1": ["index1", "index2"], "opensearch-2": ["index4"]},
        )
