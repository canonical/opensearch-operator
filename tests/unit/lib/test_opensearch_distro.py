# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from unittest.mock import patch

import responses
from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.helper_cluster import Node
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.models import DeploymentState, DeploymentType, State
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.unit.helpers import (
    mock_deployment_desc,
    mock_response_mynode,
    mock_response_nodes,
    mock_response_root,
)


class TestOpenSearchConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)

        self.config_path = "tests/unit/resources/config"
        self.charm.opensearch.config = YamlConfigSetter(base_path=self.config_path)

        # Adding Deployment Description to the Peer Relation Data
        deployment_desc = mock_deployment_desc(
            model_uuid=self.harness.charm.model.uuid,
            roles=["deployment_role1", "deployment_role2"],
            state=DeploymentState(value=State.ACTIVE),
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            temperature="warm",
        )

        with self.harness.hooks_disabled():
            self.harness.update_relation_data(
                self.rel_id,
                f"{self.charm.app.name}",
                {"deployment-description": json.dumps(deployment_desc)},
            )

    @responses.activate
    @patch("socket.socket.connect")
    def test_distro_current_online_ok(self, _):
        """Current node information retrieved from cluster state."""
        mock_response_root(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_nodes(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_mynode(self.charm.unit_name, self.charm.opensearch.host)

        node = self.charm.opensearch.current()
        assert isinstance(node, Node)
        assert node.app.name == "opensearch"
        assert node.roles == ["cluster_manager", "coordinating_only", "data", "ingest", "ml"]
        assert not node.temperature

    def test_distro_current_api_unavail_fallback_to_static_conf(self):
        """Current node attributes are to be determined from static config."""
        node = self.charm.opensearch.current()
        assert isinstance(node, Node)
        assert node.app.name == "opensearch"
        assert node.temperature == "hot"
        assert sorted(node.roles) == sorted(
            ["cluster_manager", "coordinating_only", "data", "ingest", "ml"]
        )

    # We pretend that the config file is empty
    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.load", return_value={})
    def test_distro_current_api_unavail_static_conf_unavail_fallback_to_deployment(self, _):
        """Current node attributes are to be determined from Deployment State information.

        Deployment State information is available from service startup on the Peer Relation Data.
        """
        node = self.charm.opensearch.current()
        assert isinstance(node, Node)
        assert node.app.name == "opensearch"
        assert node.roles == ["deployment_role1", "deployment_role2"]
        assert node.temperature == "warm"
