# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import os
import unittest
from unittest.mock import PropertyMock, patch

from charms.opensearch.v0.constants_charm import NodeLockRelationName, PeerRelationName
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.models import DeploymentState, DeploymentType, State
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_nodes_exclusions import VOTING_TO_DELETE
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.unit.helpers import mock_deployment_desc


class TestOpenSearchExclusions(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(True)

        self.harness.begin()

        self.charm = self.harness.charm
        self.peer_rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.lock_rel_id = self.harness.add_relation(NodeLockRelationName, self.charm.app.name)
        self.harness.add_relation_unit(self.lock_rel_id, f"{self.charm.app.name}/1")

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

    def test_add(self):
        with self.harness.hooks_disabled():
            self.charm.opensearch_exclusions.add("unit1")
            self.charm.opensearch_exclusions.add("unit2")
            self.charm.opensearch_exclusions.add("unit3")

        assert sorted(self.charm.peers_data.get(Scope.APP, VOTING_TO_DELETE).split(",")) == [
            "unit1",
            "unit2",
            "unit3",
        ]

    @patch(
        "charms.opensearch.v0.opensearch_nodes_exclusions.OpenSearchExclusions._node",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    @patch("charms.opensearch.v0.opensearch_nodes_exclusions.OpenSearchExclusions._fetch_voting")
    def test_unit_restart_and_leadership_lost(self, mock_fetch, mock_request, mock_node_method):
        """Test the change of leadership and how it impacts during a unit restart.

        The flow works as follows:
        1) Unit is the leader
        2) Unit stops, in this test: add_current() is called
        3) Unit loses leadership: in this case, the unit stops checking the Scope.APP,
           switching to Scope.UNIT
        4) Unit starts, in this test, delete_current() is called
        """

        class _node:  # noqa: N801
            def is_cm_eligible(self):
                return True

            def is_data(self):
                return True

            @property
            def name(self):
                return "testing_unit"

        mock_node_method.return_value = _node()
        mock_request.return_value = 200

        with self.harness.hooks_disabled():

            # Unit is leader
            self.harness.set_leader(True)
            # Override the self._scope:
            self.charm.opensearch_exclusions._scope = Scope.APP

            # Populate the voting_to_delete with some units
            self.charm.opensearch_exclusions.add("unit1")
            self.charm.opensearch_exclusions.add("unit2")
            self.charm.opensearch_exclusions.add("unit3")
            # Simulating the unit stop
            self.charm.opensearch_exclusions.add_current(voting=True, allocation=False)
            mock_request.assert_called_with(
                "POST",
                "/_cluster/voting_config_exclusions?node_names=testing_unit&timeout=1m",
                alt_hosts=[],
                resp_status_code=True,
                retries=3,
            )
            assert sorted(self.charm.peers_data.get(Scope.APP, VOTING_TO_DELETE).split(",")) == [
                "testing_unit",
                "unit1",
                "unit2",
                "unit3",
            ]

            # Unit loses leadership, the unit stops checking the Scope.APP
            self.harness.set_leader(False)
            # Override the self._scope:
            self.charm.opensearch_exclusions._scope = Scope.UNIT
            # Simulating the unit start, hence calling delete_current()
            mock_fetch.return_value = {"unit1", "unit2", "unit3", "testing_unit"}
            # This delete should try to remove the unit from
            # an empty VOTING_TO_DELETE set on Scope.UNIT
            self.charm.opensearch_exclusions.delete_current(voting=True, allocation=False)
            assert not self.charm.peers_data.get(Scope.UNIT, VOTING_TO_DELETE)
            mock_request.assert_any_call(
                "DELETE",
                "/_cluster/voting_config_exclusions?wait_for_removal=false",
                alt_hosts=[],
                resp_status_code=True,
            )
            mock_request.assert_called_with(
                "POST",
                "/_cluster/voting_config_exclusions?node_names=unit1,unit2,unit3&timeout=1m",
                alt_hosts=[],
                resp_status_code=True,
                retries=3,
            )

    @patch(
        "charms.opensearch.v0.opensearch_nodes_exclusions.OpenSearchExclusions._node",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    @patch("charms.opensearch.v0.opensearch_nodes_exclusions.OpenSearchExclusions._fetch_voting")
    def test_unit_restart_and_elected_as_leader(self, mock_fetch, mock_request, mock_node_method):
        """Test the inverse change: what if this unit is elected as the leader during restart.

        The flow works as follows:
        1) Unit is NOT leader
        2) Unit stops, in this test: add_current() is called
        3) Unit loses leadership: in this case, the unit stops checking the Scope.APP,
           switching to Scope.UNIT
        4) Unit starts, in this test, delete_current() is called
        """

        class _node:  # noqa: N801
            def is_cm_eligible(self):
                return True

            def is_data(self):
                return True

            @property
            def name(self):
                return "testing_unit"

        mock_node_method.return_value = _node()
        mock_request.return_value = 200

        with self.harness.hooks_disabled():
            # Unit is leader
            self.harness.set_leader(False)
            # Override the self._scope:
            self.charm.opensearch_exclusions._scope = Scope.UNIT

            # Simulating the unit stop
            self.charm.opensearch_exclusions.add_current(voting=True, allocation=False)
            mock_request.assert_called_with(
                "POST",
                "/_cluster/voting_config_exclusions?node_names=testing_unit&timeout=1m",
                alt_hosts=[],
                resp_status_code=True,
                retries=3,
            )
            assert sorted(self.charm.peers_data.get(Scope.UNIT, VOTING_TO_DELETE).split(",")) == [
                "testing_unit",
            ]

            # Unit loses leadership, the unit stops checking the Scope.APP
            self.harness.set_leader(True)
            # Override the self._scope:
            self.charm.opensearch_exclusions._scope = Scope.APP
            # Simulating the unit start, hence calling delete_current()
            mock_fetch.return_value = {"unit1", "unit2", "unit3", "testing_unit"}
            # This delete should try to remove the unit from
            # an empty VOTING_TO_DELETE set on Scope.APP
            self.charm.opensearch_exclusions.delete_current(voting=True, allocation=False)
            assert not self.charm.peers_data.get(Scope.APP, VOTING_TO_DELETE)
            mock_request.assert_any_call(
                "DELETE",
                "/_cluster/voting_config_exclusions?wait_for_removal=false",
                alt_hosts=[],
                resp_status_code=True,
            )
            mock_request.assert_called_with(
                "POST",
                "/_cluster/voting_config_exclusions?node_names=unit1,unit2,unit3&timeout=1m",
                alt_hosts=[],
                resp_status_code=True,
                retries=3,
            )
