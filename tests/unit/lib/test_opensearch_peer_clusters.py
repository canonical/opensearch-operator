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


class PatchedUnit:
    def __init__(self, name: str):
        self.name = name


class TestOpenSearchPeerClustersManager(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"
    BASE_CHARM_CLASS = f"{BASE_LIB_PATH}.opensearch_base_charm.OpenSearchBaseCharm"
    PEER_CLUSTERS_MANAGER = (
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager"
    )

    user_configs = {
        "default": PeerClusterConfig(
            cluster_name="", init_hold=False, roles=[], profile="production"
        ),
        "name": PeerClusterConfig(
            cluster_name="logs", init_hold=False, roles=[], profile="production"
        ),
        "init_hold": PeerClusterConfig(
            cluster_name="", init_hold=True, roles=[], profile="production"
        ),
        "roles_ok": PeerClusterConfig(
            cluster_name="",
            init_hold=False,
            roles=["cluster_manager", "data"],
            profile="production",
        ),
        "roles_ko": PeerClusterConfig(
            cluster_name="", init_hold=False, roles=["data"], profile="production"
        ),
        "roles_temp": PeerClusterConfig(
            cluster_name="", init_hold=True, roles=["data.hot"], profile="production"
        ),
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
        self.harness.add_network("1.1.1.1")
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.harness.add_relation(PeerRelationName, self.charm.app.name)

        self.peers_data = self.charm.peers_data

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
                    cluster_name="logs",
                    init_hold=False,
                    roles=["cluster_manager", "data"],
                    profile="production",
                ),
                start=StartMode.WITH_PROVIDED_ROLES,
                pending_directives=directives,
                app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
                typ=DeploymentType.MAIN_ORCHESTRATOR,
                state=DeploymentState(value=State.ACTIVE),
                profile="production",
            )
            can_start = self.peer_cm.can_start(deployment_desc)
            self.assertEqual(can_start, expected)

    @patch(f"{BASE_LIB_PATH}.models.PeerClusterApp.from_dict")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(f"{PEER_CLUSTERS_MANAGER}.is_provider")
    def test_validate_roles(self, is_provider, deployment_desc, peer_cluster_app_from_dict):
        """Test the roles' validation."""
        app = App(name="logs", model_uuid=self.charm.model.uuid)

        self.peers_data.get_object = MagicMock()
        peer_cluster_app_from_dict.side_effect = lambda app: MagicMock(
            planned_units=app["planned_units"]
        )

        deployment_desc.return_value = DeploymentDescription(
            config=self.user_configs["roles_ok"],
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[],
            app=App(model_uuid=self.charm.model.uuid, name="logs"),
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            state=DeploymentState(value=State.ACTIVE),
            profile="production",
        )
        # mock unit count=0 to only account for nodes in nodes list for full_cluster_planned_units
        self.charm.app.planned_units = MagicMock(return_value=0)
        is_provider.return_value = True
        # large deployment with 3 cms, should not raise an exception
        nodes = [
            Node(
                name=node.name.replace("/", "-"),
                roles=["cluster_manager"],
                ip="1.1.1.1",
                app=App(model_uuid=self.charm.model.uuid, name=app.name),
                unit_number=int(node.name.split("/")[-1]),
            )
            for node in self.p_units[0:3]
        ] + [
            Node(
                name="node",
                roles=["data"],
                ip="1.1.1.1",
                app=App(model_uuid=self.charm.model.uuid, name=app.name),
                unit_number=3,
            )
        ]

        self.peers_data.get_object.return_value = {
            "main": {"planned_units": 3},
            "data": {"planned_units": 1},
        }
        # sufficient cms in deployment
        assert self.peer_cm.has_recommended_cm_count(nodes=nodes)

        # large deployment with < 3 cms, should raise an exception on final unit
        nodes = [
            Node(
                name=node.name.replace("/", "-"),
                roles=["cluster_manager"],
                ip="1.1.1.1",
                app=App(model_uuid=self.charm.model.uuid, name=app.name),
                unit_number=int(node.name.split("/")[-1]),
            )
            for node in self.p_units[0:2]
        ] + [
            Node(
                name="node",
                roles=["data"],
                ip="0.0.0.0",
                app=App(model_uuid=self.charm.model.uuid, name="logs"),
                unit_number=2,
            )
        ]
        self.peers_data.get_object.return_value = {
            "main": {"planned_units": 2},
            "data": {"planned_units": 1},
        }

        assert not self.peer_cm.has_recommended_cm_count(nodes=nodes)

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
            profile="production",
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
                    name=node.name.replace("/", "-") + f".{deployment_desc().app.short_id}",
                    roles=["data"],
                    ip="1.1.1.1",
                    app=deployment_desc().app,
                    unit_number=int(node.name.split("/")[-1]),
                )
                for node in self.p_units
            ] + [
                Node(
                    name=f"node-5.{deployment_desc().app.short_id}",
                    roles=["data"],
                    ip="2.2.2.2",
                    app=deployment_desc().app,
                    unit_number=5,
                )
            ]
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
                    name=node.name.replace("/", "-") + f".{deployment_desc().app.short_id}",
                    roles=["data"],
                    ip="1.1.1.1",
                    app=deployment_desc().app,
                    unit_number=int(node.name.split("/")[-1]),
                )
                for node in self.p_units
            ]
            self.peer_cm._pre_validate_roles_change(new_roles=["ml"], prev_roles=["data", "ml"])
