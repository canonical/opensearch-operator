# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import unittest
from typing import List
from unittest.mock import patch

from charms.opensearch.v0.helper_cluster import ClusterState, ClusterTopology, Node
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestHelperCluster(unittest.TestCase):
    base_roles = ["data", "ingest", "ml", "coordinating_only"]
    voting_only_roles = base_roles + ["voting_only"]
    cm_roles = base_roles + ["cluster_manager"]

    def cluster_5_nodes_conf(self) -> List[Node]:
        """Returns the expected config of a 5 nodes cluster."""
        return [
            Node("cm1", self.base_roles + ["cluster_manager"], "0.0.0.1"),
            Node("cm2", self.base_roles + ["cluster_manager"], "0.0.0.2"),
            Node("cm3", self.base_roles + ["cluster_manager"], "0.0.0.3"),
            Node("voting1", self.base_roles + ["voting_only"], "0.0.0.4"),
            Node("voting2", self.base_roles + ["voting_only"], "0.0.0.5"),
        ]

    def cluster_6_nodes_conf(self):
        """Returns the expected config of a 5 nodes cluster."""
        nodes = self.cluster_5_nodes_conf()
        nodes.append(Node("data1", self.base_roles, "0.0.0.6"))
        return nodes

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _create_directories) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm

        self.opensearch = self.charm.opensearch

    def test_topology_roles_suggestion_odd_number_of_planned_units(self):
        """Test the suggestion of roles for a new node and odd numbers of planned units."""
        cluster_5_conf = self.cluster_5_nodes_conf()
        planned_units = 5

        self.assertCountEqual(ClusterTopology.suggest_roles([], planned_units), self.cm_roles)
        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_5_conf[:1], planned_units), self.cm_roles
        )
        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_5_conf[:2], planned_units), self.cm_roles
        )
        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_5_conf[:3], planned_units),
            self.voting_only_roles,
        )
        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_5_conf[:-1], planned_units),
            self.voting_only_roles,
        )

    def test_topology_roles_suggestion_even_number_of_planned_units(self):
        """Test the suggestion of roles for a new node and even numbers of planned units."""
        cluster_6_conf = self.cluster_6_nodes_conf()
        planned_units = 6

        self.assertCountEqual(ClusterTopology.suggest_roles([], planned_units), self.cm_roles)
        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_6_conf[:1], planned_units), self.cm_roles
        )
        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_6_conf[:2], planned_units), self.cm_roles
        )
        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_6_conf[:3], planned_units),
            self.voting_only_roles,
        )
        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_6_conf[:4], planned_units),
            self.voting_only_roles,
        )
        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_6_conf[:-1], planned_units), self.base_roles
        )

    def test_auto_recompute_node_roles_in_cluster_6(self):
        """Test the automatic suggestion of new roles to an existing node."""
        cluster_conf = self.cluster_6_nodes_conf()

        # remove a cluster manager node
        computed_node_to_change = ClusterTopology.node_with_new_roles(
            [node for node in cluster_conf if node.name != "cm1"]
        )
        self.assertEqual(computed_node_to_change.name, "data1")
        self.assertCountEqual(computed_node_to_change.roles, self.cm_roles)

        # remove a voting only node
        computed_node_to_change = ClusterTopology.node_with_new_roles(
            [node for node in cluster_conf if node.name != "voting1"]
        )
        self.assertEqual(computed_node_to_change.name, "data1")
        self.assertCountEqual(computed_node_to_change.roles, self.voting_only_roles)

        # remove a data node
        computed_node_to_change = ClusterTopology.node_with_new_roles(
            [node for node in cluster_conf if node.name != "data1"]
        )
        self.assertIsNone(computed_node_to_change)

    def test_node_with_new_roles_in_cluster_5(self):
        """Test the automatic suggestion of new roles to an existing node."""
        cluster_conf = self.cluster_5_nodes_conf()

        # remove a cluster manager node
        computed_node_to_change = ClusterTopology.node_with_new_roles(
            [node for node in cluster_conf if node.name != "cm1"]
        )
        self.assertTrue(computed_node_to_change.name.startswith("voting"))
        self.assertCountEqual(computed_node_to_change.roles, self.base_roles)

        # remove a voting only node
        computed_node_to_change = ClusterTopology.node_with_new_roles(
            [node for node in cluster_conf if node.name != "voting1"]
        )
        self.assertEqual(computed_node_to_change.name, "voting2")
        self.assertCountEqual(computed_node_to_change.roles, self.base_roles)

        # remove a data node
        computed_node_to_change = ClusterTopology.node_with_new_roles(
            [node for node in cluster_conf if node.name != "data1"]
        )
        self.assertIsNone(computed_node_to_change)

    def test_topology_get_cluster_managers_ips(self):
        """Test correct retrieval of cm ips from a list of nodes."""
        self.assertCountEqual(
            ClusterTopology.get_cluster_managers_ips(self.cluster_5_nodes_conf()),
            ["0.0.0.1", "0.0.0.2", "0.0.0.3"],
        )

    def test_topology_get_cluster_managers_names(self):
        """Test correct retrieval of cm ips from a list of nodes."""
        self.assertCountEqual(
            ClusterTopology.get_cluster_managers_names(self.cluster_5_nodes_conf()),
            ["cm1", "cm2", "cm3"],
        )

    def test_topology_nodes_count_by_role(self):
        """Test correct mapping role / count of nodes with the role."""
        self.assertDictEqual(
            ClusterTopology.nodes_count_by_role(self.cluster_6_nodes_conf()),
            {
                "cluster_manager": 3,
                "voting_only": 2,
                "data": 6,
                "ml": 6,
                "coordinating_only": 6,
                "ingest": 6,
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

    def test_node_obj_creation_from_json(self):
        """Test the creation of a Node object from a dict representation."""
        raw_node = Node("cm1", ["cluster_manager"], "0.0.0.11")
        from_json_node = Node.from_dict(
            {"name": "cm1", "roles": ["cluster_manager"], "ip": "0.0.0.11"}
        )

        self.assertEqual(raw_node.name, from_json_node.name)
        self.assertEqual(raw_node.roles, from_json_node.roles)
        self.assertEqual(raw_node.ip, from_json_node.ip)
