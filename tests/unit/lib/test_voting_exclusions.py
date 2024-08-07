# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
from collections import namedtuple
from unittest.mock import MagicMock, PropertyMock

import charms
import pytest
import tenacity
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.models import DeploymentType
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


# The Node class is mocked using namedtuple:
class MockNode:
    def __init__(self, name):
        self.name = name

    def is_cm_eligible(self):
        return True

    def is_voting_only(self):
        return True


DeploymentDescription = namedtuple("DeploymentDescription", ["typ"])
PeerCMRelData = namedtuple("PeerCMRelData", ["cm_nodes"])


@pytest.fixture(scope="function")
def harness():
    harness_obj = Harness(OpenSearchOperatorCharm)
    harness_obj.begin()

    charms.opensearch.v0.opensearch_nodes_exclusions.stop_after_delay = MagicMock(
        return_value=tenacity.stop.stop_after_delay(0.2)
    )
    charms.opensearch.v0.opensearch_nodes_exclusions.wait_fixed = MagicMock(
        return_value=tenacity.wait.wait_fixed(0.1)
    )
    type(harness_obj.charm).alt_hosts = PropertyMock()
    harness_obj.charm._put_or_update_internal_user_leader = MagicMock()

    harness_obj.charm.opensearch_exclusions._fetch_voting_exclusions = MagicMock(return_value={})
    harness_obj.charm.opensearch_peer_cm.deployment_desc = MagicMock(
        return_value=DeploymentType.MAIN_ORCHESTRATOR
    )

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
    exclusions.delete_allocations = MagicMock(return_value=alloc_exclusion_ret)
    exclusions.allocation_cleanup()
    exclusions.delete_allocations.assert_called_with(allocs.split(","))
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

    assert (
        exclusions._add_voting(alt_hosts=charm.alt_hosts, node_names=node_names)
        != http_error_happens
    )
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

    assert exclusions._delete_voting(charm.alt_hosts) != http_error_happens
    exclusions._opensearch.request.assert_called_with(
        "DELETE",
        "/_cluster/voting_config_exclusions?wait_for_removal=false",
        alt_hosts=charm.alt_hosts,
        resp_status_code=True,
    )


# Test charm's voting exclusion settlement
# This test will run over settle_voting method on the three main exceptions:
# Only one CM node
# Two CM nodes
# Many CM nodes available


# The parameters set here are:
# 1) is_main: whether the deployment is a main orchestrator or not
# 2) cm_node_list: the list of CM nodes
# 3) is_stopping: whether the charm is stopping or not
# 4) elected_manager: the elected manager node
# 5) Result of the settle processing expected: which units should be excluded here
# 6) fetch_voting_set: returns the set of voting exclusions before we do any updates
# 7) should_update_voting: whether the voting should be updated or not
# 8) retry: this parameter is set to True on update_status
@pytest.mark.parametrize(
    "is_main,cm_node_list,is_stopping,elected_manager,excluded_cm_names,"
    "fetch_voting_set,should_update_voting,retry",
    [
        # 1st test: scaling 1->0, with 1x unit from the start
        (
            True,  # is_main
            [MockNode("thisnode")],  # thisnode only
            True,  # is going away
            None,  # We will not reach the check of elected manager
            [],
            {},  # No voting exclusions, this test assumes a single unit from the start
            True,  # Always called
            True,
        ),
        # 2nd test: single unit cluster, but this unit is not stopping -> called on update_status
        (
            True,  # is_main
            [MockNode("thisnode")],  # thisnode only
            False,  # is not going away
            None,  # we will skip the check as we are working with 1-unit cluster
            [],
            {},  # No voting exclusions, this test assumes a single unit from the start
            True,  # We are assuming a single unit cluster that does not change
            False,
        ),
        # 3rd test: this node restarted, 2x units, where this node is not stopping
        (
            True,  # is_main
            [MockNode("thisnode"), MockNode("node1")],  # thisnode and node1
            False,  # is not going away
            MockNode("thisnode"),  # thisnode is the final elected manager
            ["node1"],  # exclude node1 in this case, as we have two nodes
            {},  # We are moving from 1->2 nodes, we should not have any voting exclusions
            True,  # An update must happen here
            True,
        ),
        # 4th test: scaling 2->1, where this node is stopping
        # This test will not change voting exclusions, as this node is already excluded
        (
            True,  # is_main
            [MockNode("thisnode"), MockNode("node1")],  # thisnode and node1
            True,  # is going away
            None,  # elected leader, we are not going to check as the rule will stay unchanged
            ["thisnode"],  # as we are going away, we apply the exclusion rule
            {"thisnode"},  # We have a previous voting exclusion
            False,  # we should not call delete/add voting here as thisnode is already excluded
            False,  # we should not call delete/add voting here as thisnode is already excluded
        ),
        # 5th test: scaling 2->1, where this node is stopping but not in original voting exclusions
        (
            True,  # is_main
            [MockNode("thisnode"), MockNode("node1")],  # thisnode and node1
            True,  # is going away
            MockNode("node1"),  # elected leader
            ["thisnode"],  # as we are going away, we apply the exclusion rule
            {"node1"},  # We have a previous voting exclusion
            True,  # we have to reset the exclusions
            True,
        ),
        # 6th test: scaling 3->2, where this is the node stopping
        (
            True,  # is_main
            [MockNode("thisnode"), MockNode("node1"), MockNode("node2")],  # thisnode and node1
            True,  # is going away
            MockNode("node2"),  # thisnode is the final elected manager
            ["thisnode", "node1"],  # two nodes are excluded, to enforce node2 to be elected
            {},
            True,
            True,
        ),
    ],
)
def test_settle_voting(
    harness,
    is_main,
    cm_node_list,
    is_stopping,
    elected_manager,
    excluded_cm_names,
    fetch_voting_set,
    should_update_voting,
    retry,
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
    charm.opensearch.is_node_up = MagicMock(return_value=True)

    charm.opensearch_peer_cm.deployment_desc = MagicMock(
        return_value=__create_deployment_desc(is_main)
    )
    # Only the lead units are interesting in this test scenario anyways
    charm.unit.is_leader = MagicMock(return_value=True)

    charm.opensearch_peer_cm.rel_data = MagicMock(return_value=__rel_data(cm_node_list))
    ClusterTopology.nodes = MagicMock(return_value=cm_node_list)
    ClusterTopology.elected_manager = MagicMock(return_value=elected_manager)
    charm.opensearch_exclusions._fetch_voting_exclusions = MagicMock(return_value=fetch_voting_set)
    charm.opensearch_exclusions._delete_voting = MagicMock()
    charm.opensearch_exclusions._add_voting = MagicMock()

    # Call the method:
    charm.opensearch_exclusions.settle_voting(is_stopping, retry=retry)

    # Now, validate the results
    if should_update_voting:
        charm.opensearch_exclusions._delete_voting.assert_called_once()
    else:
        charm.opensearch_exclusions._delete_voting.assert_not_called()

    if elected_manager:
        charm.opensearch_exclusions._add_voting.assert_called_once_with(
            charm.alt_hosts, node_names=excluded_cm_names
        )
        ClusterTopology.elected_manager.assert_called_once()
    else:
        charm.opensearch_exclusions._add_voting.assert_not_called()
        ClusterTopology.elected_manager.assert_not_called()
