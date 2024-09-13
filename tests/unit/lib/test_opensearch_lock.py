# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import os
import unittest
from unittest.mock import patch

import responses
from charms.opensearch.v0.constants_charm import NodeLockRelationName, PeerRelationName
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.models import DeploymentState, DeploymentType, State
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.unit.helpers import (
    get_relation_unit,
    mock_deployment_desc,
    mock_response_nodes,
    mock_response_root,
)


class TestOpenSearchLock(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
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

    def test_node_lock_no_online_hosts_init_leader(self):
        """Initially no one has the lock if there is a leader"""
        self.harness.set_leader(is_leader=True)

        assert self.harness.get_relation_data(self.lock_rel_id, self.charm.app.name) == {}
        assert self.harness.get_relation_data(self.lock_rel_id, self.charm.unit.name) == {}
        assert self.harness.get_relation_data(self.lock_rel_id, f"{self.charm.app.name}/0") == {}

    @responses.activate
    @patch("socket.socket.connect")
    def test_node_lock_has_online_hosts_init_leader(self, _):
        # Initializing mocks showing the unit online in the cluster
        mock_response_root(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_nodes(self.charm.unit_name, self.charm.opensearch.host)
        """Initially no one has the lock if there is a leader"""
        self.harness.set_leader(is_leader=True)

        assert self.harness.get_relation_data(self.lock_rel_id, self.charm.app.name) == {}
        assert self.harness.get_relation_data(self.lock_rel_id, self.charm.unit.name) == {}
        assert self.harness.get_relation_data(self.lock_rel_id, f"{self.charm.app.name}/0") == {}

    def test_node_lock_no_online_hosts_leader_acquire_lock_via_databag(self):
        # The leader does not have the lock at this moment, but starts "queuing up"
        # If the charm code raises an uncaught exception later in the Juju event
        self.harness.set_leader(is_leader=True)
        self.harness.update_relation_data(
            self.lock_rel_id, f"{self.charm.app.name}", {"unit-with-lock": ""}
        )
        assert not self.harness.charm.node_lock.acquired

        assert (
            self.harness.get_relation_data(self.lock_rel_id, f"{self.charm.unit.name}")[
                "lock-requested"
            ]
            == "true"
        )

        # A new event introduces a new Juju context ID
        # At this point the leader can take the lock
        os.environ["JUJU_CONTEXT_ID"] = "new-context-id"
        assert self.harness.charm.node_lock.acquired

    @responses.activate
    @patch("socket.socket.connect")
    def test_node_lock_has_online_nodes_leader_acquire_lock_via_document(self, _):
        # Initializing mocks showing the unit online in the cluster
        mock_response_root(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_nodes(self.charm.unit_name, self.charm.opensearch.host)

        # No unit has the lock at this moment
        expected_response = {"unit-name": ""}

        responses.add(
            method="GET",
            url=f"https://{self.charm.opensearch.host}:9200/.charm_node_lock/0",
            json=expected_response,
            status=200,
        )

        # The leader does not have the lock at this moment, but starts "queuing up"
        # If the charm code raises an uncaught exception later in the Juju event
        self.harness.set_leader(is_leader=True)
        self.harness.update_relation_data(
            self.lock_rel_id, f"{self.charm.app.name}", {"unit-with-lock": ""}
        )
        assert not self.harness.charm.node_lock.acquired

        assert (
            self.harness.get_relation_data(self.lock_rel_id, f"{self.charm.unit.name}")[
                "lock-requested"
            ]
            == "true"
        )

        # A new event introduces a new Juju context ID
        # At this point the leader can take the lock
        os.environ["JUJU_CONTEXT_ID"] = "new-context-id"
        assert self.harness.charm.node_lock.acquired

    def test_node_lock_no_online_nodes_departing_node_doesnt_break(self):
        """Departing unit may be part of the relation while having no entry in the databag.

        # https://github.com/canonical/opensearch-operator/issues/323
        """
        # The leader does not have the lock at this moment, but starts "queuing up"
        # If the charm code raises an uncaught exception later in the Juju event
        self.harness.set_leader(is_leader=True)
        self.harness.update_relation_data(
            self.lock_rel_id, f"{self.charm.app.name}", {"unit-with-lock": ""}
        )

        # We simulate that a departing node is still part of the relation
        # however has no more data in the databag
        unit1 = get_relation_unit(
            self.harness.model, NodeLockRelationName, f"{self.harness.charm.app.name}/1"
        )
        databag = self.harness.charm.model.get_relation(NodeLockRelationName).data
        databag._data.pop(unit1)

        # The property function executes healthy
        # instead of breaking over the unit missing from the databag
        assert not self.harness.charm.node_lock.acquired

    @responses.activate
    @patch("socket.socket.connect")
    def test_node_lock_has_online_nodes_departing_node_doesnt_break(self, _):
        """Departing unit may be part of the relation while having no entry in the databag.

        # https://github.com/canonical/opensearch-operator/issues/323
        """
        # Initializing mocks showing the unit online in the cluster
        mock_response_root(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_nodes(self.charm.unit_name, self.charm.opensearch.host)

        # No unit has the lock at this moment
        expected_response = {"unit-name": ""}

        responses.add(
            method="GET",
            url=f"https://{self.charm.opensearch.host}:9200/.charm_node_lock/0",
            json=expected_response,
            status=200,
        )

        # The leader does not have the lock at this moment, but starts "queuing up"
        # If the charm code raises an uncaught exception later in the Juju event
        self.harness.set_leader(is_leader=True)
        self.harness.update_relation_data(
            self.lock_rel_id, f"{self.charm.app.name}", {"unit-with-lock": ""}
        )

        # We simulate that a departing node is still part of the relation
        # however has no more data in the databag
        unit1 = get_relation_unit(
            self.harness.model, NodeLockRelationName, f"{self.harness.charm.app.name}/1"
        )
        databag = self.harness.charm.model.get_relation(NodeLockRelationName).data
        databag._data.pop(unit1)

        # The property function executes healthy
        # instead of breaking over the unit missing from the databag
        assert not self.harness.charm.node_lock.acquired
