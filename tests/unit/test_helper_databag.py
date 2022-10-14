# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest

from charms.opensearch.v0.helper_cluster import ClusterTopology, Node


class TestHelperCluster(unittest.TestCase):
    def setUp(self) -> None:
        self.cluster_topology = ClusterTopology()
        self.nodes_0 = []
        self.nodes_1 = [Node("cm1", ["cluster_manager", "data"], "2.2.2.2")]
        self.nodes_2 = self.nodes_1 + [Node("data1", ["voting_only", "data"], "2.2.2.3")]
        self.nodes_3 = self.nodes_2 + [Node("cm2", ["cluster_manager", "data"], "2.2.2.4")]
        self.nodes_4 = self.nodes_3 + [Node("data2", ["data"], "2.2.2.5")]

    def test_roles_suggestion(self):
        """Test the suggestion of roles for a new node."""
        self.assertCountEqual(
            self.cluster_topology.suggest_roles(self.nodes_0), ["cluster_manager", "data"]
        )
        self.assertCountEqual(
            self.cluster_topology.suggest_roles(self.nodes_1), ["voting_only", "data"]
        )
        self.assertCountEqual(
            self.cluster_topology.suggest_roles(self.nodes_2), ["cluster_manager", "data"]
        )
        self.assertCountEqual(self.cluster_topology.suggest_roles(self.nodes_3), ["data"])

    def test_is_cluster_bootstrapped(self):
        """Test if cluster is bootstrapped."""
        self.assertFalse(self.cluster_topology.is_cluster_bootstrapped(self.nodes_0))
        self.assertFalse(self.cluster_topology.is_cluster_bootstrapped(self.nodes_1))
        self.assertFalse(self.cluster_topology.is_cluster_bootstrapped(self.nodes_2))
        self.assertTrue(self.cluster_topology.is_cluster_bootstrapped(self.nodes_3))
        self.assertTrue(self.cluster_topology.is_cluster_bootstrapped(self.nodes_4))

    def test_get_cluster_managers_ips(self):
        """Test correct retrieval of cm ips from a list of nodes."""
        self.assertCountEqual(
            self.cluster_topology.get_cluster_managers_ips(self.nodes_4), ["2.2.2.2", "2.2.2.4"]
        )

    def test_get_cluster_managers_names(self):
        """Test correct retrieval of cm ips from a list of nodes."""
        self.assertCountEqual(
            self.cluster_topology.get_cluster_managers_names(self.nodes_4), ["cm1", "cm2"]
        )

    def test_nodes_count_by_role(self):
        """Test correct mapping role / count of nodes with the role."""
        self.assertDictEqual(
            self.cluster_topology.nodes_count_by_role(self.nodes_4),
            {
                "cluster_manager": 2,
                "voting_only": 1,
                "data": 4,
            },
        )
