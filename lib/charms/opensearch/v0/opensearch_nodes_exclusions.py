# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for OpenSearch node exclusions management."""
import logging
from functools import cached_property
from typing import List, Optional, Set

from charms.opensearch.v0.models import Node
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
VOTING_TO_DELETE = "delete-voting-exclusions"


class OpenSearchExclusions:
    """Exclusions related operations, important to reason as exclusions, NOT additions."""

    def __init__(self, charm):
        self._charm = charm
        self._opensearch = self._charm.opensearch

        self._scope = Scope.APP if self._charm.unit.is_leader() else Scope.UNIT

    def add_current(self, restart: bool = False) -> None:
        """Add Voting and alloc exclusions."""
        if self._node.is_cm_eligible() or self._node.is_voting_only():
            if self._add_voting():
                self._charm.peers_data.put(
                    self._scope,
                    VOTING_TO_DELETE,
                    ",".join(self._fetch_voting_exclusions()),
                )
            else:
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
                    VOTING_TO_DELETE,
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

    def cleanup(self) -> None:
        """Delete all exclusions that failed to be deleted."""
        need_voting_cleanup = set(
            self._charm.peers_data.get(self._scope, VOTING_TO_DELETE, "").split(",")
        )
        if (
            need_voting_cleanup
            and self._delete_voting(to_remove=need_voting_cleanup)
            and not self._fetch_voting_exclusions()  # called after the entire deletion, must be empty now
        ):
            self._charm.peers_data.delete(self._scope, VOTING_TO_DELETE)

        allocations_to_cleanup = self._charm.peers_data.get(
            self._scope, ALLOCS_TO_DELETE, ""
        ).split(",")
        if allocations_to_cleanup and self.delete_allocations(allocations_to_cleanup):
            self._charm.peers_data.delete(self._scope, ALLOCS_TO_DELETE)

    def _add_voting(self, exclusions: Optional[Set[str]] = None) -> bool:
        """Include the current node in the CMs voting exclusions list of nodes."""
        try:
            to_add = exclusions or set([self._node.name])
            self._opensearch.request(
                "POST",
                f"/_cluster/voting_config_exclusions?node_names={','.join(to_add)}&timeout=1m",
                alt_hosts=self._charm.alt_hosts,
                resp_status_code=True,
                retries=3,
            )
            return to_add is not None
        except OpenSearchHttpError:
            return False

    def _delete_voting(self, to_remove: Optional[Set[str]] = None) -> Optional[Set[str]]:
        """Remove all the voting exclusions - cannot target 1 exclusion at a time."""
        # "wait_for_removal" is VERY important, it removes all voting configs immediately
        # and allows any node to return to the voting config in the future
        original_exclusions = exclusions = self._fetch_voting_exclusions()
        try:
            self._opensearch.request(
                "DELETE",
                "/_cluster/voting_config_exclusions?wait_for_removal=false",
                alt_hosts=self._charm.alt_hosts,
                resp_status_code=True,
            )
            remove_set = to_remove or set([self._node.name])
            for node in remove_set:
                if node in exclusions:
                    exclusions.remove(node)
                    remove_set.remove(node)
            if exclusions and exclusions != original_exclusions:
                self._add_voting(exclusions)
            return remove_set is None
        except OpenSearchHttpError:
            return False

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
