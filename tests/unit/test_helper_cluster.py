# Copyright 2022 Canonical Ltd.
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

        self.nodes_0 = []
        self.nodes_1 = [Node("cm1", ["cluster_manager", "data"], "2.2.2.2")]
        self.nodes_2 = self.nodes_1 + [Node("data1", ["voting_only", "data"], "2.2.2.3")]
        self.nodes_3 = self.nodes_2 + [Node("cm2", ["cluster_manager", "data"], "2.2.2.4")]
        self.nodes_4 = self.nodes_3 + [Node("data2", ["data"], "2.2.2.5")]

    def test_topology_roles_suggestion(self):
        """Test the suggestion of roles for a new node."""
        self.assertCountEqual(
            ClusterTopology.suggest_roles(self.nodes_0), ["cluster_manager", "data"]
        )
        self.assertCountEqual(ClusterTopology.suggest_roles(self.nodes_1), ["voting_only", "data"])
        self.assertCountEqual(
            ClusterTopology.suggest_roles(self.nodes_2), ["cluster_manager", "data"]
        )
        self.assertCountEqual(ClusterTopology.suggest_roles(self.nodes_3), ["data"])

    def test_remaining_nodes_for_bootstrap(self):
        """Test if cluster is bootstrapped."""
        self.assertTrue(self.cluster_topology.remaining_nodes_for_bootstrap(self.nodes_0) == 3)
        self.assertTrue(self.cluster_topology.remaining_nodes_for_bootstrap(self.nodes_1) == 2)
        self.assertTrue(self.cluster_topology.remaining_nodes_for_bootstrap(self.nodes_2) == 1)
        self.assertTrue(self.cluster_topology.remaining_nodes_for_bootstrap(self.nodes_3) == 0)
        self.assertTrue(self.cluster_topology.remaining_nodes_for_bootstrap(self.nodes_4) == 0)

    def test_get_cluster_managers_ips(self):
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
