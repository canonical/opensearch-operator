# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import os
import unittest
from unittest.mock import patch

from charms.opensearch.v0.models import OpenSearchPerfProfile
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.unit.helpers import mock_deployment_desc


def test_perf_profile():
    with patch("charms.opensearch.v0.models.OpenSearchPerfProfile.meminfo") as mock_perf_profile:
        mock_perf_profile.return_value = {"MemTotal": ("10240", "mB")}
        charm = OpenSearchPerfProfile.from_str("production")
        assert charm.profile == mock_perf_profile.return_value


"""
class TestPerformanceProfile(unittest.TestCase):

    def setUp(self):
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(True)

        self.harness.begin()

        self.charm = self.harness.charm
        self.peer_rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)

        self.config_path = "tests/unit/resources/config"
        self.charm.opensearch.config = YamlConfigSetter(base_path=self.config_path)

        # Adding Deployment Description to the Peer Relation Data
        deployment_desc = mock_deployment_desc(
            model_uuid=self.harness.charm.model.uuid,
            roles=["cluster_manager", "coordinating_only", "data"],
            state=DeploymentState(value=State.ACTIVE),
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            temperature="warm",
        )

        with self.harness.hooks_disabled():
            self.harness.update_relation_data(
                self.peer_rel_id,
                f"{self.charm.app.name}",
                {"deployment-description": json.dumps(deployment_desc)},
            )

        self.juju_context_id = "juju-context-id"
        os.environ["JUJU_CONTEXT_ID"] = self.juju_context_id


    def test_initial_state(self):
        # Test the initial state of the performance profile
        self.assertEqual(self.profile.state, 'initial')

    def test_update_performance_metrics(self):
        # Test updating performance metrics
        self.profile.update_metrics(cpu_usage=50, memory_usage=1024)
        self.assertEqual(self.profile.cpu_usage, 50)
        self.assertEqual(self.profile.memory_usage, 1024)

    def test_reset_performance_metrics(self):
        # Test resetting performance metrics
        self.profile.update_metrics(cpu_usage=50, memory_usage=1024)
        self.profile.reset_metrics()
        self.assertEqual(self.profile.cpu_usage, 0)
        self.assertEqual(self.profile.memory_usage, 0)

if __name__ == '__main__':
    unittest.main()
"""
