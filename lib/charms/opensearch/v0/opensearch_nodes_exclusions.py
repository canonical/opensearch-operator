# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for OpenSearch node exclusions management."""
import logging
from functools import cached_property
from typing import List, Optional, Set

from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.models import DeploymentType, Node
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from tenacity import Retrying, stop_after_delay, wait_fixed

# The unique Charmhub library identifier, never change it
LIBID = "51c1ac864e9a4d12b1d1ef27c0ff2e50"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


ALLOCS_TO_DELETE = "allocation-exclusions-to-delete"


class OpenSearchExclusionError(OpenSearchError):
    """Base class for OpenSearch exclusions errors."""


class OpenSearchExclusionNodeNotRegisteredError(OpenSearchExclusionError):
    """Error when a node is not in the list of nodes."""


class OpenSearchExclusionElectedManagerNotFoundError(OpenSearchExclusionError):
    """Error when the elected manager is not in the list of nodes."""


class OpenSearchExclusions:
    """Exclusions related operations, important to reason as exclusions, NOT additions."""

    def __init__(self, charm):
        self._charm = charm
        self._opensearch = self._charm.opensearch

        self._scope = Scope.APP if self._charm.unit.is_leader() else Scope.UNIT

    def add_allocations(
        self, allocations: Optional[Set[str]] = None, override: bool = False
    ) -> bool:
        """Register new allocation exclusions."""
        try:
            existing = set() if override else self._fetch_allocations()
            all_allocs = existing.union(
                allocations if allocations is not None else {self._node.name}
            )
            response = self._opensearch.request(
                "PUT",
                "/_cluster/settings",
                {"persistent": {"cluster.routing.allocation.exclude._name": ",".join(all_allocs)}},
                alt_hosts=self._charm.alt_hosts,
            )
            return "acknowledged" in response
        except OpenSearchHttpError:
            return False

    def delete_allocations(self, allocs: Optional[List[str]] = None) -> None:
        """Delete Voting and alloc exclusions."""
        try:
            existing = self._fetch_allocations()
            to_remove = set(allocs if allocs is not None else [self._node.name])
            res = self.add_allocations(existing - to_remove, override=True)
            return res
        except OpenSearchHttpError:
            return False

    def allocation_cleanup(self) -> None:
        """Delete alloc exclusions that failed to be deleted."""
        allocations_to_cleanup = self._charm.peers_data.get(
            self._scope, ALLOCS_TO_DELETE, ""
        ).split(",")
        if allocations_to_cleanup and self.delete_allocations(allocations_to_cleanup):
            self._charm.peers_data.delete(self._scope, ALLOCS_TO_DELETE)

    def _add_voting(
        self, alt_hosts: Optional[List[str]] = None, node_names: Optional[List[str]] = None
    ) -> bool:
        """Include the current node in the CMs voting exclusions list of nodes.

        If node_names is not specified, then the current node is excluded for compatibility.
        """
        if set(node_names or []) == self._fetch_voting_exclusions(alt_hosts):
            # no need to add the same nodes again
            return True

        add_nodes = "&node_names=" + (",".join(node_names) if node_names else self._node.name)
        try:
            self._opensearch.request(
                "POST",
                "/_cluster/voting_config_exclusions?timeout=1m" + add_nodes,
                alt_hosts=alt_hosts,
                resp_status_code=True,
                retries=3,
            )
            return True
        except OpenSearchHttpError:
            return False

    def _delete_voting(self, alt_hosts: Optional[List[str]] = None) -> bool:
        """Remove all the voting exclusions - cannot target 1 exclusion at a time."""
        # "wait_for_removal" is VERY important, it removes all voting configs immediately
        # and allows any node to return to the voting config in the future
        try:
            self._opensearch.request(
                "DELETE",
                "/_cluster/voting_config_exclusions?wait_for_removal=false",
                alt_hosts=alt_hosts,
                resp_status_code=True,
            )
            return True
        except OpenSearchHttpError:
            return False

    def settle_voting(self, unit_is_stopping: bool = False, retry: bool = True):  # noqa C901
        """Settle the voting exclusions for all voting units.

        The voting exclusion management assures that the cluster has the right number of CMs
        in special cases such as single or double units. If we cannot carefully manage this
        situation, then we may end up with a cluster with corrupted metadata.

        This function will assign voting exclusions based on the current available CMs.

        The voting exclusion will only happen as we enter the "2x CMs" scenario. During this time,
        we will exclude some nodes and ensure the cluster manager has been settled. Once the
        cluster changes to a <2 or >2 node scenario, then we clean up the voting exclusions.

        Args:
            unit_is_stopping:
                If the unit is stopping, it must be excluded from the voting always
                and we should consider only the remaining CMs
            retry:
                If the operation should retry its internal checks or fail right away

        Raises:
            OpenSearchHttpError:
                Any HTTP error that happens during the request.
            OpenSearchExclusionNodeNotRegisteredError:
                The unit is not in the list of nodes.
            OpenSearchExclusionElectedManagerNotFoundError:
                The elected manager is not in the list of nodes
        """
        # To avoid any race conditions, only the juju leader of the MAIN cluster will manage the
        # voting OR we have a unit that is stopping, in this case we may have to update
        # voting exclusions.
        if not unit_is_stopping and (
            self._charm.opensearch_peer_cm.deployment_desc().typ
            != DeploymentType.MAIN_ORCHESTRATOR
            and not self._charm.unit.is_leader()
        ):
            return

        stop_delay = 300
        wait_time = 10

        for attempt in Retrying(
            stop=stop_after_delay(stop_delay), wait=wait_fixed(wait_time), reraise=True
        ):
            with attempt:
                nodes = ClusterTopology.nodes(
                    self._charm.opensearch,
                    self._charm.opensearch.is_node_up(),
                    self._charm.alt_hosts,
                )

                node = None
                for n in nodes:
                    if n.name == self._charm.unit_name:
                        if not n.is_cm_eligible() and not n.is_voting_only():
                            # Nothing to do here, this is a unit that IS stopping but cannot vote
                            return
                        node = n
                        break

                if unit_is_stopping and node:
                    # This is a stop operation, we exclude the unit that is stopping
                    # if still in the list
                    nodes.remove(node)
                    # we can finish the for loop here

                elif not unit_is_stopping and not node and self._charm.opensearch.is_started():
                    # If this unit was supposed to be active but not in the node list, then there
                    # is an issue with the ClusterTopology.nodes() output
                    raise OpenSearchExclusionNodeNotRegisteredError()

                # Any other case is okay to move forward without changes
                # not unit_is_stopping and     node: normal checks from the MAIN leader
                #     unit_is_stopping and not node: expected if we have a unit going away

        sorted_cm_names = sorted(ClusterTopology.get_cluster_managers_names(nodes))
        # For the sake of predictability, we always sort the cluster managers
        current_exclusions = self._fetch_voting_exclusions(self._charm.alt_hosts)
        logger.debug(f"Current voting exclusions: {current_exclusions}")

        new_exclusions = []

        # Each of the possible cases
        if len(sorted_cm_names) == 1:
            if unit_is_stopping:
                # This condition only happens IF the cluster had 2x units and now scale down to 1
                # In this scenario, exclude the node that is going away, to force election
                # to the remaining unit.
                new_exclusions.append(self._charm.unit_name)
            else:
                # In the case this unit is not stopping: we do not need to have voting exclusions
                self._delete_voting(self._charm.alt_hosts)
                return

        elif len(sorted_cm_names) == 2:
            if unit_is_stopping:
                # Down scaling from 3->2 units, where this unit is going away
                # Remove both this unit and the first sorted_cm_names from the voting
                new_exclusions.extend([self._charm.unit_name, sorted_cm_names[0]])
            else:
                # We are adding this unit to the cluster and we've waited until it is present
                # We only exclude one unit:
                new_exclusions.append(sorted_cm_names[0])

        else:
            # In this case, we either are scaling down to 0 or len(cms) > 2.
            # There is nothing more to do then cleanup the exclusions
            self._delete_voting(self._charm.alt_hosts)
            return

        #  Ensures that we can have a 3 node cluster restart safely:
        #   3->2 nodes (this unit stops)
        #     Now, we have 2 units -> we need to manage the voting exclusions by removing both
        #     this unit and an extra unit from the cluster
        #   2 nodes:
        #     The new_exclusions will have only the sorted_cm_namess[0] unit. We keep the current
        #     voting exclusions configuration.
        #   2->3 nodes:
        #     This unit has came back online -> it must power up (still 1x unit as voter), once the
        #     unit is online, we will call the settle_voting again and fall in
        #     len(sorted_cm_names) == 3, where we will delete all voting exclusions.
        finished = True
        for node in new_exclusions:
            if node not in current_exclusions:
                # There is a node that needs to be excluded
                finished = False

        if finished:
            logger.debug("Voting exclusions are already set")
            return

        logger.debug("Setting new voting exclusions")
        self._delete_voting(self._charm.alt_hosts)
        self._add_voting(self._charm.alt_hosts, node_names=new_exclusions)

        if not retry:
            stop_delay = 0
            wait_time = 0

        # We have a change where we are scaling up / down into the 2-unit scenario
        # Now, we must be sure a new manager is elected, or there was a failure
        for attempt in Retrying(
            stop=stop_after_delay(stop_delay), wait=wait_fixed(wait_time), reraise=True
        ):
            with attempt:
                manager = ClusterTopology.elected_manager(
                    self._charm.opensearch,
                    use_localhost=self._charm.opensearch.is_node_up(),
                    hosts=self._charm.alt_hosts,
                )
                if not manager or manager.name in new_exclusions:
                    raise OpenSearchExclusionElectedManagerNotFoundError()

    def _fetch_allocations(self) -> Set[str]:
        """Fetch the registered allocation exclusions."""
        allocation_exclusions = set()
        try:
            resp = self._opensearch.request(
                "GET", "/_cluster/settings", alt_hosts=self._charm.alt_hosts
            )
            exclusions = resp["persistent"]["cluster"]["routing"]["allocation"]["exclude"]["_name"]
            if exclusions:
                allocation_exclusions = set(exclusions.split(","))
        except KeyError:
            # no allocation exclusion set
            pass
        finally:
            return allocation_exclusions

    def _fetch_voting_exclusions(self, alt_hosts) -> Set[str]:
        """Fetch the registered voting exclusions."""
        hosts = alt_hosts if alt_hosts else self._charm.alt_hosts
        try:
            resp = self._opensearch.request(
                "GET", "/_cluster/state/metadata/voting_config_exclusions", alt_hosts=hosts
            )
            return set(
                sorted(
                    [
                        node["node_name"]
                        for node in resp["metadata"]["cluster_coordination"][
                            "voting_config_exclusions"
                        ]
                    ]
                )
            )
        except OpenSearchHttpError as e:
            logger.warning(f"Failed to fetch voting exclusions: {e}")
            # no voting exclusion set
            return {}

    @cached_property
    def _node(self) -> Node:
        """Returns current node."""
        return self._charm.opensearch.current()
