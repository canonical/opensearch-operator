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


class OpenSearchExclusions:
    """Exclusions related operations, important to reason as exclusions, NOT additions."""

    def __init__(self, charm):
        self._charm = charm
        self._opensearch = self._charm.opensearch

        self._scope = Scope.APP if self._charm.unit.is_leader() else Scope.UNIT

    def allocation_cleanup(self) -> None:
        """Delete alloc exclusions that failed to be deleted."""
        allocations_to_cleanup = self._charm.peers_data.get(
            self._scope, ALLOCS_TO_DELETE, ""
        ).split(",")
        if allocations_to_cleanup and self.delete_allocations_exclusion(allocations_to_cleanup):
            self._charm.peers_data.delete(self._scope, ALLOCS_TO_DELETE)

    def add_voting(
        self, alt_hosts: Optional[List[str]] = None, node_names: Optional[List[str]] = None
    ) -> bool:
        """Include the node_names list in the CMs voting exclusions."""
        add_nodes = "&node_names=" + (",".join(node_names) if node_names else self._node.name)
        try:
            self._opensearch.request(
                "POST",
                "/_cluster/voting_config_exclusions?timeout=1m" + add_nodes,
                alt_hosts=alt_hosts if alt_hosts else self._charm.alt_hosts,
                resp_status_code=True,
                retries=3,
            )
            return True
        except OpenSearchHttpError:
            return False

    def delete_voting(self, alt_hosts: Optional[List[str]] = None) -> bool:
        """Remove all the voting exclusions - cannot target 1 exclusion at a time."""
        # "wait_for_removal" is VERY important, it removes all voting configs immediately
        # and allows any node to return to the voting config in the future
        try:
            self._opensearch.request(
                "DELETE",
                "/_cluster/voting_config_exclusions?wait_for_removal=false",
                alt_hosts=alt_hosts if alt_hosts else self._charm.alt_hosts,
                resp_status_code=True,
            )
            return True
        except OpenSearchHttpError:
            return False

    def add_allocations_exclusion(
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

    def delete_allocations_exclusion(self, allocs: Optional[List[str]] = None) -> bool:
        """This removes the allocation exclusions if needed."""
        try:
            existing = self._fetch_allocations()
            to_remove = set(allocs if allocs is not None else [self._node.name])
            res = self.add_allocations_exclusion(existing - to_remove, override=True)
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
