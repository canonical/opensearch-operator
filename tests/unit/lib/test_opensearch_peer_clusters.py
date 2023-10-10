# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_peer_clusters library."""
import unittest
from unittest.mock import MagicMock, PropertyMock, patch

from charms.opensearch.v0.opensearch_peer_clusters import (
    OpenSearchProvidedRolesException,
)
from ops import Relation
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from lib.charms.opensearch.v0.constants_charm import PeerRelationName
from lib.charms.opensearch.v0.models import (
    DeploymentDescription,
    DeploymentState,
    DeploymentType,
    Directive,
    Node,
    PeerClusterConfig,
    StartMode,
    State,
)
from tests.helpers import patch_network_get


class PatchedUnit:
    def __init__(self, name: str):
        self.name = name


@patch_network_get("1.1.1.1")
class TestOpenSearchPeerClustersManager(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"
    BASE_CHARM_CLASS = f"{BASE_LIB_PATH}.opensearch_base_charm.OpenSearchBaseCharm"
    PEER_CLUSTERS_MANAGER = (
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager"
    )

    user_configs = {
        "default": PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
        "name": PeerClusterConfig(cluster_name="logs", init_hold=False, roles=[]),
        "init_hold": PeerClusterConfig(cluster_name="", init_hold=True, roles=[]),
        "roles_ok": PeerClusterConfig(
            cluster_name="", init_hold=False, roles=["cluster_manager", "data"]
        ),
        "roles_ko": PeerClusterConfig(cluster_name="", init_hold=False, roles=["data"]),
        "roles_temp": PeerClusterConfig(cluster_name="", init_hold=True, roles=["data.hot"]),
    }

    units = [
        PatchedUnit(name="opensearch/0"),
        PatchedUnit(name="opensearch/1"),
        PatchedUnit(name="opensearch/2"),
        PatchedUnit(name="opensearch/3"),
        PatchedUnit(name="opensearch/4"),
    ]

    @patch("charm.OpenSearchOperatorCharm._put_admin_user")
    def setUp(self, _put_admin_user) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.harness.add_relation(PeerRelationName, self.charm.app.name)

        self.opensearch = self.charm.opensearch
        self.opensearch.is_node_up = MagicMock(return_value=True)
        self.peer_cm = self.charm.opensearch_peer_cm

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    def test_can_start(self, deployment_desc):
        """Test the can_start logic."""
        deployment_desc.return_value = None
        self.assertFalse(self.peer_cm.can_start())

        # with different directives
        for directives, expected in [
            ([], True),
            ([Directive.SHOW_STATUS], True),
            ([Directive.SHOW_STATUS, Directive.WAIT_FOR_PEER_CLUSTER_RELATION], False),
            ([Directive.INHERIT_CLUSTER_NAME], False),
        ]:
            deployment_desc = DeploymentDescription(
                config=PeerClusterConfig(
                    cluster_name="logs", init_hold=False, roles=["cluster_manager", "data"]
                ),
                start=StartMode.WITH_PROVIDED_ROLES,
                directives=directives,
                typ=DeploymentType.MAIN_CLUSTER_MANAGER,
                state=DeploymentState(value=State.ACTIVE),
            )
            can_start = self.peer_cm.can_start(deployment_desc)
            self.assertEqual(can_start, expected)

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    def test_validate_roles(self, deployment_desc):
        """Test the roles' validation."""
        Relation.units = PropertyMock(return_value=self.units)
        deployment_desc.return_value = DeploymentDescription(
            config=self.user_configs["roles_ok"],
            start=StartMode.WITH_PROVIDED_ROLES,
            directives=[],
            typ=DeploymentType.MAIN_CLUSTER_MANAGER,
            state=DeploymentState(value=State.ACTIVE),
        )
        with self.assertRaises(OpenSearchProvidedRolesException):
            # on scale up
            self.charm.app.planned_units = MagicMock(return_value=4)
            nodes = [
                Node(
                    name=node.name.replace("/", "-"),
                    roles=["cluster_manager", "data"],
                    ip="1.1.1.1",
                )
                for node in self.units[0:3]
            ]
            self.peer_cm.validate_roles(nodes=nodes, on_new_unit=True)

        with self.assertRaises(OpenSearchProvidedRolesException):
            # on rebalance
            self.charm.app.planned_units = MagicMock(return_value=5)
            nodes = [
                Node(
                    name=node.name.replace("/", "-"),
                    roles=["cluster_manager", "data"],
                    ip="1.1.1.1",
                )
                for node in self.units[0:4]
            ] + [Node(name="node", roles=["ml"], ip="0.0.0.0")]
            self.peer_cm.validate_roles(nodes=nodes, on_new_unit=False)

    @patch(f"{BASE_LIB_PATH}.helper_cluster.ClusterTopology.nodes")
    @patch(f"{BASE_CHARM_CLASS}.alt_hosts")
    @patch(f"{PEER_CLUSTERS_MANAGER}.is_peer_cluster_relation_set")
    def test_pre_validate_roles_change(self, is_peer_cluster_relation_set, alt_hosts, nodes):
        """Test the pre_validation of roles change."""
        Relation.units = PropertyMock(return_value=self.units)
        alt_hosts.return_value = []

        try:
            self.peer_cm._pre_validate_roles_change(
                new_roles=["data", "ml"], prev_roles=["data", "ml"]
            )
            self.peer_cm._pre_validate_roles_change(new_roles=[], prev_roles=["data", "ml"])

            # test on a multi clusters fleet - happy path
            is_peer_cluster_relation_set.return_value = True
            nodes.return_value = [
                Node(name=node.name.replace("/", "-"), roles=["data"], ip="1.1.1.1")
                for node in self.units
            ] + [Node(name="node-5", roles=["data"], ip="2.2.2.2")]
            self.peer_cm._pre_validate_roles_change(new_roles=["ml"], prev_roles=["data", "ml"])
        except OpenSearchProvidedRolesException:
            self.fail("_pre_validate_roles_change() failed unexpectedly.")

        with self.assertRaises(OpenSearchProvidedRolesException):
            self.peer_cm._pre_validate_roles_change(
                new_roles=["cluster_manager", "voting_only"], prev_roles=[]
            )
        with self.assertRaises(OpenSearchProvidedRolesException):
            self.peer_cm._pre_validate_roles_change(
                new_roles=["data"], prev_roles=["cluster_manager", "data"]
            )
        with self.assertRaises(OpenSearchProvidedRolesException):
            is_peer_cluster_relation_set.return_value = False
            self.peer_cm._pre_validate_roles_change(new_roles=["ml"], prev_roles=["ml", "data"])
        with self.assertRaises(OpenSearchProvidedRolesException):
            # no other data nodes in cluster fleet
            is_peer_cluster_relation_set.return_value = True
            nodes.return_value = [
                Node(name=node.name.replace("/", "-"), roles=["data"], ip="1.1.1.1")
                for node in self.units
            ]
            self.peer_cm._pre_validate_roles_change(new_roles=["ml"], prev_roles=["data", "ml"])
