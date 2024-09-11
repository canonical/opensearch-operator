# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for OpenSearch node exclusions management."""
import logging
from functools import cached_property
from typing import List, Optional, Set

from charms.opensearch.v0.constants_charm import (
    PeerClusterOrchestratorRelationName,
    PeerRelationName,
)
from charms.opensearch.v0.helper_charm import format_unit_name
from charms.opensearch.v0.models import DeploymentType, Node
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope

# The unique Charmhub library identifier, never change it
LIBID = "51c1ac864e9a4d12b1d1ef27c0ff2e50"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


ALLOCS_TO_DELETE = "allocation-exclusions-to-delete"
CURRENT_EXCLUSIONS = "current-voting-exclusions"


class OpenSearchExclusions:
    """Exclusions related operations, important to reason as exclusions, NOT additions."""

    def __init__(self, charm):
        self._charm = charm
        self._opensearch = self._charm.opensearch

        self._scope = Scope.APP if self._charm.unit.is_leader() else Scope.UNIT

    def add_current(self, restart: bool = False) -> None:
        """Add Voting and alloc exclusions."""
        if self._node.is_cm_eligible() or self._node.is_voting_only():
            if not self._add_voting():
                logger.error(f"Failed to add voting exclusion: {self._node.name}.")

        if not restart:
            if self._node.is_data() and not self.add_allocations():
                logger.error(f"Failed to add shard allocation exclusion: {self._node.name}.")

    def delete_current(self) -> None:
        """Delete Voting and alloc exclusions."""
        if self._node.is_cm_eligible() or self._node.is_voting_only():
            if self._delete_voting():
                self._charm.peers_data.put(
                    self._scope,
                    CURRENT_EXCLUSIONS,
                    ",".join(self._fetch_voting_exclusions()),
                )
            else:
                logger.error(f"Failed to exclude voting exclusion: {self._node.name}.")

        if self._node.is_data() and not self.delete_allocations():
            current_allocations = set(
                self._charm.peers_data.get(self._scope, ALLOCS_TO_DELETE, "").split(",")
            )
            current_allocations.add(self._node.name)

            self._charm.peers_data.put(
                self._scope, ALLOCS_TO_DELETE, ",".join(current_allocations)
            )

    def _removed_units_to_cleanup(self) -> Optional[List[str]]:
        """Deletes all units that have left the cluster via Juju.

        This method ensures we keep a small list of voting exclusions at all times.
        """
        deployment_desc = self._charm.opensearch_peer_cm.deployment_desc()
        if not deployment_desc or deployment_desc.typ not in [
            DeploymentType.MAIN_ORCHESTRATOR,
        ]:
            return []

        # We do not need to add our own unit as this code is running on it!
        peers = self._charm.model.get_relation(PeerRelationName)
        peers = [] if not peers else peers.units

        cms = set(
            [
                format_unit_name(unit)
                for relation in self._charm.model.relations.get(
                    PeerClusterOrchestratorRelationName
                )
                for unit in relation.units
            ]
            + [format_unit_name(unit) for unit in peers]
        )

        cleanup_nodes = []
        for node in self._fetch_voting_exclusions():
            if node not in cms:
                cleanup_nodes.append(node)
        return cleanup_nodes

    def cleanup(self) -> None:
        """Delete all exclusions that failed to be deleted."""
        # Dealing with voting exclusions:
        self._delete_voting(cleanup_this_node=False)

        # Now, dealing with allocation cleanup
        allocations_to_cleanup = self._charm.peers_data.get(
            self._scope, ALLOCS_TO_DELETE, ""
        ).split(",")
        if allocations_to_cleanup and self.delete_allocations(allocations_to_cleanup):
            self._charm.peers_data.delete(self._scope, ALLOCS_TO_DELETE)

    def _add_voting(self, exclusions: Optional[Set[str]] = None) -> bool:
        """Include the current node in the CMs voting exclusions list of nodes."""
        try:
            to_add = exclusions or {self._node.name}
            self._opensearch.request(
                "POST",
                f"/_cluster/voting_config_exclusions?node_names={','.join(to_add)}&timeout=1m",
                alt_hosts=self._charm.alt_hosts,
                resp_status_code=True,
                retries=3,
            )
            logger.debug(f"Added voting for {to_add}: SUCCESS")
            self._charm.add_to_peer_data(CURRENT_EXCLUSIONS, list(to_add))

            return to_add is not None
        except OpenSearchHttpError:
            logger.debug(f"Added voting for {to_add}: FAILED")
            return False

    def _delete_voting(self, cleanup_this_node: bool = True) -> Optional[Set[str]]:
        """Remove all the voting exclusions - cannot target 1 exclusion at a time."""
        # First, we start by calculating the list of exclusions
        # that will stay, given this node is leaving
        to_readd = self._cleanup_voting_list([self._node.name])
        try:
            # "wait_for_removal" is VERY important, it removes all voting configs immediately
            # and allows any node to return to the voting config in the future
            self._opensearch.request(
                "DELETE",
                "/_cluster/voting_config_exclusions?wait_for_removal=false",
                alt_hosts=self._charm.alt_hosts,
                resp_status_code=True,
            )
            logger.debug("Removed voting")
            # We've cleaned up the entire list, now we can re-add the ones that should stay
            if to_readd:
                self._add_voting(to_readd)
        except OpenSearchHttpError:
            logger.debug("Removed voting: FAILED")
            return False

    def _cleanup_voting_list(self, to_remove: Optional[List[str]] = []) -> Optional[List[str]]:
        """Cleanup the voting exclusions that are no longer part of the charm.

        1) Recover the list of exclusions set by the charm
        2) Fetch the list of units in the exclusions that are not part of the charm anymore
        3) Prepare the cleanup: any unit name present in CURRENT_EXCLUSIONS and in the removed list
        """
        current_exclusions = self._charm.peers_data.get(self._scope, CURRENT_EXCLUSIONS, "").split(
            ","
        )
        logger.debug(
            f"Cleanup voting exclusions - original value in peer data: {current_exclusions}"
        )

        removed_units = self._removed_units_to_cleanup()
        for unit in current_exclusions:
            if unit in removed_units or unit in to_remove:
                current_exclusions.remove(unit)
        logger.debug(
            f"Cleanup voting exclusions - removed: {removed_units} and kept {current_exclusions}"
        )

        self._update_peer_data(CURRENT_EXCLUSIONS, current_exclusions)
        return current_exclusions

    def _fetch_voting_exclusions(self) -> Set[str]:
        """Fetch the registered voting exclusions."""
        try:
            resp = self._opensearch.request(
                "GET",
                "/_cluster/state/metadata/voting_config_exclusions",
                alt_hosts=self._charm.alt_hosts,
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
        except (OpenSearchHttpError, KeyError) as e:
            logger.warning(f"Failed to fetch voting exclusions: {e}")
            # no voting exclusion set
            return {}

    def add_allocations(
        self, allocations: Optional[Set[str]] = None, override: bool = False
    ) -> bool:
        """Register new allocation exclusions."""
        try:
            existing = set() if override else self._fetch_allocations()
            all_allocs = existing.union(
                allocations if allocations is not None else set([self._node.name])
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

    def delete_allocations(self, allocs: Optional[List[str]] = None) -> bool:
        """This removes the allocation exclusions if needed."""
        try:
            existing = self._fetch_allocations()
            to_remove = set(allocs if allocs is not None else [self._node.name])
            res = self.add_allocations(existing - to_remove, override=True)
            return res
        except OpenSearchHttpError:
            return False

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

    @cached_property
    def _node(self) -> Node:
        """Returns current node."""
        return self._charm.opensearch.current()

    def _update_peer_data(self, key: str, values: Optional[List[str]]) -> None:
        """Add a new set of values to the peers data.

        If values == None, then remove key's content.
        """
        if not values:
            self._charm.peers_data.put(
                self._scope,
                key,
                "",
            )
            return
        current_values = self._charm.peers_data.get(self._scope, key, "").split(",")
        self._charm.peers_data.put(
            self._scope,
            key,
            ",".join(set(current_values + values)),
        )
