# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
from collections import namedtuple
from unittest.mock import MagicMock, PropertyMock

import charms
import pytest
import tenacity
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from lib.charms.opensearch.v0.models import DeploymentType


# The Node class is mocked using namedtuple:
class MockNode:
    def __init__(self, name):
        self.name = name

    def is_cm_eligible(self):
        return True


DeploymentDescription = namedtuple("DeploymentDescription", ["typ"])
PeerCMRelData = namedtuple("PeerCMRelData", ["cm_nodes"])


@pytest.fixture(scope="function")
def harness():
    harness_obj = Harness(OpenSearchOperatorCharm)
    # charms.opensearch.v0.opensearch_base_charm.OpenSearchPeerClustersManager.deployment_desc = (
    #     MagicMock(return_value=create_deployment_desc())
    # )
    harness_obj.begin()
    # charm = harness_obj.charm

    harness_obj.set_leader(is_leader=True)
    charms.opensearch.v0.opensearch_base_charm.stop_after_delay = MagicMock(
        return_value=tenacity.stop.stop_after_delay(0.2)
    )
    charms.opensearch.v0.opensearch_base_charm.wait_fixed = MagicMock(
        return_value=tenacity.wait.wait_fixed(0.1)
    )
    type(harness_obj.charm).alt_hosts = PropertyMock()

    return harness_obj


# Models the allocations to be deleted
# There are two parameters:
# 1) The content of peers_data, i.e. a comma-separated list of allocation exclusions
# 2) The return value of the delete_allocations_exclusion method, which may clean up the peer
#    relation or not
@pytest.mark.parametrize(
    "allocs,alloc_exclusion_ret",
    [
        ("allocation1,allocation2", True),
        # Failed to delete the allocations, so the peer relation is not cleaned up
        ("allocation1,allocation2", False),
        # This is a broken scenario, where delete_allocations_exclusion returns mistakenly
        # True for a empty list
        ("", True),
    ],
)
def test_allocation_cleanup(harness, allocs, alloc_exclusion_ret):
    charm = harness.charm
    exclusions = charm.opensearch_exclusions

    charm.peers_data.get = MagicMock(return_value=allocs)
    charm.peers_data.delete = MagicMock()
    exclusions.delete_allocations_exclusion = MagicMock(return_value=alloc_exclusion_ret)
    exclusions.allocation_cleanup()
    exclusions.delete_allocations_exclusion.assert_called_with(allocs.split(","))
    if alloc_exclusion_ret:
        charm.peers_data.delete.assert_called_with(Scope.UNIT, "allocation-exclusions-to-delete")
    else:
        charm.peers_data.delete.assert_not_called()


# Models addition of voting exclusions
# There are 2x parameters:
# 1) node names to be added to the voting exclusion
# 2) An error is simulated by the OpenSearchHttpError exception
@pytest.mark.parametrize(
    "node_names,http_error_happens",
    [([], False), (["node2", "node3"], False), (["node2", "node3"], True)],
)
def test_add_voting(harness, node_names, http_error_happens):
    charm = harness.charm
    exclusions = charm.opensearch_exclusions
    this_node = MockNode("node1")

    exclusions._opensearch.request = MagicMock()

    type(exclusions)._node = PropertyMock(return_value=this_node)
    if not http_error_happens:
        exclusions._opensearch.request.return_value = None
    else:
        exclusions._opensearch.request.side_effect = OpenSearchHttpError

    assert exclusions.add_voting(node_names=node_names) != http_error_happens
    exclusions._opensearch.request.assert_called_with(
        "POST",
        "/_cluster/voting_config_exclusions?timeout=1m&node_names="
        + ",".join(node_names if node_names else [this_node.name]),
        alt_hosts=charm.alt_hosts,
        resp_status_code=True,
        retries=3,
    )


# Models removal of voting exclusions
# There are 1x parameter:
# 1) An error is simulated by the OpenSearchHttpError exception
@pytest.mark.parametrize(
    "http_error_happens",
    [
        (False),
        (True),
    ],
)
def test_delete_voting(harness, http_error_happens):
    charm = harness.charm
    exclusions = charm.opensearch_exclusions
    exclusions._opensearch.request = MagicMock()

    if not http_error_happens:
        exclusions._opensearch.request.return_value = None
    else:
        exclusions._opensearch.request.side_effect = OpenSearchHttpError

    assert exclusions.delete_voting() != http_error_happens
    exclusions._opensearch.request.assert_called_with(
        "DELETE",
        "/_cluster/voting_config_exclusions?wait_for_removal=false",
        alt_hosts=charm.alt_hosts,
        resp_status_code=True,
    )


# Test charm's voting exclusion settlement
# This test will run over _settle_voting_exclusions method on the three main exceptions:
# Only one CM node
# Two CM nodes
# Many CM nodes available


# The parameters set here are:
# 1) is_main: whether the deployment is a main orchestrator or not
# 2) cm_node_list: the list of CM nodes
# 3) is_stopping: whether the charm is stopping or not
# 4) elected_manager: the elected manager node
# 5) Result of the settle processing expected: which units should be excluded here
@pytest.mark.parametrize(
    "is_main,cm_node_list,is_stopping,elected_manager,excluded_cm_names",
    [
        # 1st test: scaling 1->0
        (
            True,  # is_main
            [MockNode("thisnode")],  # thisnode only
            True,  # is going away
            None,  # We will not reach the check of elected manager
            [],
        ),
        # 2nd test: single unit cluster, but this unit is not stopping
        (
            True,  # is_main
            [MockNode("thisnode")],  # thisnode only
            False,  # is not going away
            MockNode("thisnode"),  # thisnode is the final elected manager
            [],
        ),
        # 3rd test: 2x units, where this node is not stopping
        (
            True,  # is_main
            [MockNode("thisnode"), MockNode("node1")],  # thisnode and node1
            False,  # is not going away
            MockNode("thisnode"),  # thisnode is the final elected manager
            ["node1"],  # exclude node1 in this case, as we have two nodes
        ),
        # 4th test: scaling 2->1, where this node is stopping
        (
            True,  # is_main
            [MockNode("thisnode"), MockNode("node1")],  # thisnode and node1
            True,  # is going away
            MockNode("node1"),  # elected leader
            ["thisnode"],  # as we are going away, we apply the exclusion rule
        ),
        # 5th test: scaling 3->2, where this is the node stopping
        (
            True,  # is_main
            [MockNode("thisnode"), MockNode("node1"), MockNode("node2")],  # thisnode and node1
            True,  # is going away
            MockNode("node2"),  # thisnode is the final elected manager
            ["thisnode", "node1"],  # two nodes are excluded, to enforce node2 to be elected
        ),
        # 6th test: scaling 3->2, where this is not the node stopping
        # This test is the same as 3rd test scenario
    ],
)
def test_settle_voting_exclusions(
    harness, is_main, cm_node_list, is_stopping, elected_manager, excluded_cm_names
):

    def __create_deployment_desc(is_main=True):
        return DeploymentDescription(
            typ=(
                DeploymentType.MAIN_ORCHESTRATOR
                if is_main
                else DeploymentType.FAILOVER_ORCHESTRATOR
            ),
        )

    def __rel_data(cm_node_list):
        return PeerCMRelData(cm_nodes=cm_node_list)

    charm = harness.charm
    type(charm).unit_name = PropertyMock(return_value="thisnode")
    charm.opensearch_peer_cm.deployment_desc = MagicMock(
        return_value=__create_deployment_desc(is_main)
    )
    charm.opensearch_peer_cm.rel_data = MagicMock(return_value=__rel_data(cm_node_list))
    ClusterTopology.nodes = MagicMock(return_value=cm_node_list)
    # ClusterTopology.get_cluster_managers_names = MagicMock(
    #     return_value=[cm_node.name for cm_node in cm_node_list]
    # )
    ClusterTopology.elected_manager = MagicMock(return_value=elected_manager)
    charm.opensearch_exclusions.delete_voting = MagicMock()
    charm.opensearch_exclusions.add_voting = MagicMock()

    # Call the method:
    charm._settle_voting_exclusions(is_stopping)

    # Now, validate the results
    charm.opensearch_exclusions.delete_voting.assert_called_once()

    if excluded_cm_names:
        charm.opensearch_exclusions.add_voting.assert_called_once_with(
            charm.alt_hosts, node_names=excluded_cm_names
        )
    else:
        charm.opensearch_exclusions.add_voting.assert_not_called()

    if elected_manager:
        ClusterTopology.elected_manager.assert_called_once()
    else:
        ClusterTopology.elected_manager.assert_not_called()
