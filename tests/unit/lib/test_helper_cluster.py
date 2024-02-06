# Copyright 2023 Canonical Ltd.
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
    cm_roles = base_roles + ["cluster_manager"]

    cluster1 = "cluster1"
    cluster2 = "cluster2"

    def cluster1_5_nodes_conf(self) -> List[Node]:
        """Returns the expected config of a 5 "planned" nodes cluster."""
        return [
            Node(name="cm1", roles=self.cm_roles, ip="0.0.0.1", app_name=self.cluster1),
            Node(name="cm2", roles=self.cm_roles, ip="0.0.0.2", app_name=self.cluster1),
            Node(name="cm3", roles=self.cm_roles, ip="0.0.0.3", app_name=self.cluster1),
            Node(name="cm4", roles=self.cm_roles, ip="0.0.0.4", app_name=self.cluster1),
            Node(name="cm5", roles=self.cm_roles, ip="0.0.0.5", app_name=self.cluster1),
        ]

    def cluster1_6_nodes_conf(self):
        """Returns the expected config of a 6 "planned" nodes cluster."""
        nodes = self.cluster1_5_nodes_conf()
        nodes.append(
            Node(name="data1", roles=self.base_roles, ip="0.0.0.6", app_name=self.cluster1)
        )
        return nodes

    def cluster2_nodes_conf(self) -> List[Node]:
        """Returns the expected config of the sub-cluster 2."""
        roles = ["cluster_manager", "data", "ml"]
        return [
            Node(name="cm_data_ml1", roles=roles, ip="0.0.0.11", app_name=self.cluster2),
            Node(name="cm_data_ml2", roles=roles, ip="0.0.0.12", app_name=self.cluster2),
            Node(name="cm_data_ml3", roles=roles, ip="0.0.0.13", app_name=self.cluster2),
            Node(name="cm_data_ml4", roles=roles, ip="0.0.0.14", app_name=self.cluster2),
            Node(name="cm_data_ml5", roles=roles, ip="0.0.0.15", app_name=self.cluster2),
        ]

    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm

        self.opensearch = self.charm.opensearch

    def test_topology_roles_suggestion_odd_number_of_planned_units(self):
        """Test the suggestion of roles for a new node and odd numbers of planned units."""
        planned_units = 5
        cluster_5_conf = self.cluster1_5_nodes_conf()

        self.assertCountEqual(ClusterTopology.suggest_roles([], planned_units), self.cm_roles)
        for start_index in range(1, 5):
            self.assertCountEqual(
                ClusterTopology.suggest_roles(cluster_5_conf[:start_index], planned_units),
                self.cm_roles,
            )

    def test_topology_roles_suggestion_even_number_of_planned_units(self):
        """Test the suggestion of roles for a new node and even numbers of planned units."""
        cluster_6_conf = self.cluster1_6_nodes_conf()

        planned_units = 6

        self.assertCountEqual(ClusterTopology.suggest_roles([], planned_units), self.cm_roles)
        for start_index in range(1, 5):
            self.assertCountEqual(
                ClusterTopology.suggest_roles(cluster_6_conf[:start_index], planned_units),
                self.cm_roles,
            )

        self.assertCountEqual(
            ClusterTopology.suggest_roles(cluster_6_conf[:-1], planned_units), self.base_roles
        )

    def test_auto_recompute_node_roles_in_cluster_6(self):
        """Test the automatic suggestion of new roles to an existing node."""
        cluster_conf = self.cluster1_6_nodes_conf()

        # remove a cluster manager node
        computed_node_to_change = ClusterTopology.node_with_new_roles(
            app_name=self.cluster1,
            remaining_nodes=[node for node in cluster_conf if node.name != "cm1"],
        )
        self.assertEqual(computed_node_to_change.name, "data1")
        self.assertCountEqual(computed_node_to_change.roles, self.cm_roles)

        # remove a data node
        computed_node_to_change = ClusterTopology.node_with_new_roles(
            app_name=self.cluster1,
            remaining_nodes=[node for node in cluster_conf if node.name != "data1"],
        )
        self.assertIsNone(computed_node_to_change)

    def test_auto_recompute_node_roles_in_cluster_5(self):
        """Test the automatic suggestion of new roles to an existing node."""
        cluster_conf = self.cluster1_5_nodes_conf()

        # remove a cluster manager node
        computed_node_to_change = ClusterTopology.node_with_new_roles(
            app_name=self.cluster1,
            remaining_nodes=[node for node in cluster_conf if node.name != "cm1"],
        )
        self.assertCountEqual(computed_node_to_change.roles, self.base_roles)

    def test_auto_recompute_node_roles_in_previous_non_auto_gen_cluster(self):
        """Test the automatic suggestion of new roles to an existing node."""
        cluster_conf = self.cluster2_nodes_conf()

        # first cluster
        first_cluster_nodes = []
        for node in self.cluster1_5_nodes_conf():
            new_node = node.copy()
            new_node.roles.append("custom_role")
            first_cluster_nodes.append(new_node)

        # remove a cluster manager node
        computed_node_to_change = ClusterTopology.recompute_nodes_conf(
            app_name=self.cluster2,
            nodes=cluster_conf + first_cluster_nodes,
        )

        expected = {node.name: node for node in first_cluster_nodes}
        for node in self.cluster2_nodes_conf():
            expected[node.name] = Node(
                name=node.name,
                roles=self.cm_roles,
                ip=node.ip,
                app_name=node.app_name,
                temperature=node.temperature,
            )
        self.assertCountEqual(computed_node_to_change, expected)

    def test_topology_get_cluster_managers_ips(self):
        """Test correct retrieval of cm ips from a list of nodes."""
        self.assertCountEqual(
            ClusterTopology.get_cluster_managers_ips(self.cluster1_5_nodes_conf()),
            ["0.0.0.1", "0.0.0.2", "0.0.0.3", "0.0.0.4", "0.0.0.5"],
        )

    def test_topology_get_cluster_managers_names(self):
        """Test correct retrieval of cm ips from a list of nodes."""
        self.assertCountEqual(
            ClusterTopology.get_cluster_managers_names(self.cluster1_5_nodes_conf()),
            ["cm1", "cm2", "cm3", "cm4", "cm5"],
        )

    def test_topology_nodes_count_by_role(self):
        """Test correct mapping role / count of nodes with the role."""
        self.assertDictEqual(
            ClusterTopology.nodes_count_by_role(self.cluster1_6_nodes_conf()),
            {
                "cluster_manager": 5,
                "coordinating_only": 6,
                "data": 6,
                "ingest": 6,
                "ml": 6,
            },
        )

    def test_refill_node_with_default_roles(self):
        """Test the automatic suggestion of new roles to an existing node."""
        # First test with previously set roles in a cluster
        cluster2_nodes = self.cluster2_nodes_conf()

        expected = []
        for node in cluster2_nodes:
            expected.append(
                Node(
                    name=node.name,
                    roles=self.cm_roles,
                    ip=node.ip,
                    app_name=node.app_name,
                    temperature=node.temperature,
                )
            )
        expected.sort(key=lambda node: node.name)
        refilled = ClusterTopology.refill_node_with_default_roles(
            app_name=self.cluster2,
            nodes=cluster2_nodes,
        )
        refilled.sort(key=lambda node: node.name)
        for index in range(len(refilled)):
            self.assertEqual(refilled[index], expected[index])

        # test on auto-gen roles: expected no changes
        expected = self.cluster1_5_nodes_conf()
        expected.sort(key=lambda node: node.name)
        refilled = ClusterTopology.refill_node_with_default_roles(
            app_name=self.cluster1,
            nodes=self.cluster1_5_nodes_conf(),
        )
        refilled.sort(key=lambda node: node.name)
        for index in range(len(refilled)):
            self.assertEqual(refilled[index], expected[index])

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
        raw_node = Node(
            name="cm1", roles=["cluster_manager"], ip="0.0.0.11", app_name=self.cluster1
        )
        from_json_node = Node.from_dict(
            {
                "name": "cm1",
                "roles": ["cluster_manager"],
                "ip": "0.0.0.11",
                "app_name": self.cluster1,
            }
        )

        self.assertEqual(raw_node.name, from_json_node.name)
        self.assertEqual(raw_node.roles, from_json_node.roles)
        self.assertEqual(raw_node.ip, from_json_node.ip)

    @patch("charms.opensearch.v0.helper_cluster.OpenSearchDistribution.request")
    def test_get_cluster_settings(self, request_mock):
        """Test the get_cluster_settings method."""
        request_mock.return_value = {
            "persistent": {
                "knn.plugin.enabled": "true",
                "cluster.routing.allocation.enable": "all",
            },
            "transient": {
                "indices.recovery.max_bytes_per_sec": "50mb",
            },
        }

        expected_settings = {
            "knn.plugin.enabled": "true",
            "cluster.routing.allocation.enable": "all",
            "indices.recovery.max_bytes_per_sec": "50mb",
        }

        settings = ClusterTopology.get_cluster_settings(
            self.opensearch,
            include_defaults=True,
        )

        self.assertEqual(settings, expected_settings)
        request_mock.assert_called_once_with(
            "GET",
            "/_cluster/settings?flat_settings=true&include_defaults=true",
            host=None,
            alt_hosts=None,
        )
