# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_peer_clusters library."""
import unittest
from unittest.mock import MagicMock, patch

from charms.opensearch.v0.opensearch_peer_clusters import (
    OpenSearchProvidedRolesException,
)
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from lib.charms.opensearch.v0.constants_charm import PeerRelationName
from lib.charms.opensearch.v0.models import (
    App,
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

    p_units = [
        PatchedUnit(name="opensearch/0"),
        PatchedUnit(name="opensearch/1"),
        PatchedUnit(name="opensearch/2"),
        PatchedUnit(name="opensearch/3"),
        PatchedUnit(name="opensearch/4"),
    ]

    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def setUp(self, _) -> None:
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
                pending_directives=directives,
                app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
                typ=DeploymentType.MAIN_ORCHESTRATOR,
                state=DeploymentState(value=State.ACTIVE),
            )
            can_start = self.peer_cm.can_start(deployment_desc)
            self.assertEqual(can_start, expected)

    @patch(f"{PEER_CLUSTERS_MANAGER}.is_peer_cluster_orchestrator_relation_set")
    @patch("ops.model.Model.get_relation")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    def test_validate_roles(
        self, deployment_desc, get_relation, is_peer_cluster_orchestrator_relation_set
    ):
        """Test the roles' validation."""
        is_peer_cluster_orchestrator_relation_set.return_value = False
        get_relation.return_value.units = set(self.p_units)

        deployment_desc.return_value = DeploymentDescription(
            config=self.user_configs["roles_ok"],
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[],
            app=App(model_uuid=self.charm.model.uuid, name="logs"),
            typ=DeploymentType.MAIN_ORCHESTRATOR,
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
                    app=App(model_uuid=self.charm.model.uuid, name="logs"),
                    unit_number=int(node.name.split("/")[-1]),
                )
                for node in self.p_units[0:3]
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
                    app=App(model_uuid=self.charm.model.uuid, name="logs"),
                    unit_number=int(node.name.split("/")[-1]),
                )
                for node in self.p_units[0:4]
            ] + [
                Node(
                    name="node",
                    roles=["ml"],
                    ip="0.0.0.0",
                    app=App(model_uuid=self.charm.model.uuid, name="logs"),
                    unit_number=7,
                )
            ]
            self.peer_cm.validate_roles(nodes=nodes, on_new_unit=False)

    @patch("ops.model.Model.get_relation")
    @patch(f"{BASE_LIB_PATH}.helper_cluster.ClusterTopology.nodes")
    @patch(f"{BASE_CHARM_CLASS}.alt_hosts")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(f"{PEER_CLUSTERS_MANAGER}.is_peer_cluster_orchestrator_relation_set")
    def test_pre_validate_roles_change(
        self,
        is_peer_cluster_orchestrator_relation_set,
        deployment_desc,
        alt_hosts,
        nodes,
        get_relation,
    ):
        """Test the pre_validation of roles change."""
        get_relation.return_value.units = set(self.p_units)

        deployment_desc.return_value = DeploymentDescription(
            config=self.user_configs["roles_ok"],
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[],
            app=App(model_uuid=self.charm.model.uuid, name="logs"),
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            state=DeploymentState(value=State.ACTIVE),
        )

        alt_hosts.return_value = []
        try:
            self.peer_cm._pre_validate_roles_change(
                new_roles=["data", "ml"], prev_roles=["data", "ml"]
            )
            self.peer_cm._pre_validate_roles_change(new_roles=[], prev_roles=["data", "ml"])

            # test on a multi clusters fleet - happy path
            is_peer_cluster_orchestrator_relation_set.return_value = True
            nodes.return_value = [
                Node(
                    name=node.name.replace("/", "-") + f".{deployment_desc().app.id}",
                    roles=["data"],
                    ip="1.1.1.1",
                    app=deployment_desc().app,
                    unit_number=int(node.name.split("/")[-1]),
                )
                for node in self.p_units
            ] + [
                Node(
                    name=f"node-5.{deployment_desc().app.id}",
                    roles=["data"],
                    ip="2.2.2.2",
                    app=deployment_desc().app,
                    unit_number=5,
                )
            ]
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
            is_peer_cluster_orchestrator_relation_set.return_value = False
            self.peer_cm._pre_validate_roles_change(new_roles=["ml"], prev_roles=["ml", "data"])
        with self.assertRaises(OpenSearchProvidedRolesException):
            # no other data nodes in cluster fleet
            is_peer_cluster_orchestrator_relation_set.return_value = True
            nodes.return_value = [
                Node(
                    name=node.name.replace("/", "-") + f".{deployment_desc().app.id}",
                    roles=["data"],
                    ip="1.1.1.1",
                    app=deployment_desc().app,
                    unit_number=int(node.name.split("/")[-1]),
                )
                for node in self.p_units
            ]
            self.peer_cm._pre_validate_roles_change(new_roles=["ml"], prev_roles=["data", "ml"])
