# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for OpenSearch node exclusions management."""
import logging
from typing import List, Optional, Set, Union

from charms.opensearch.v0.constants_charm import (
    AllocationExclusionFailed,
    HorizontalScaleUpSuggest,
    VotingExclusionFailed,
)
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.opensearch_distro import (
    OpenSearchDistribution,
    OpenSearchError,
    OpenSearchHttpError,
)
from ops.model import BlockedStatus, MaintenanceStatus

# The unique Charmhub library identifier, never change it
LIBID = "51c1ac864e9a4d12b1d1ef27c0ff2e50"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class NodeExclusionInCharmOps:
    """Node exclusions related operations in the charm."""

    RemoveFromAllocExclusion = "remove_from_allocation_exclusions"
    RemoveVotingExclusions = "remove_voting_exclusions"

    def __init__(self, charm):
        self._charm = charm

    def on_allocation_exclusion_add_failed(self):
        """Callback for when the OpenSearch service fails stopping."""
        self._charm.unit.status = BlockedStatus(AllocationExclusionFailed)

    def on_voting_exclusion_add_failed(self):
        """Callback for when a ClusterManager node voting exclusion fails."""
        self._charm.unit.status = BlockedStatus(VotingExclusionFailed)

    def on_unassigned_shards(self, unassigned_shards: int):
        """Called during node shutdown / horizontal scale-down if some shards left unassigned."""
        self._charm.app.status = MaintenanceStatus(
            HorizontalScaleUpSuggest.format(unassigned_shards)
        )

    def set_voting_exclusions_for_removal(self) -> None:
        """Store a flag in the relation data bag, to clear ALL voting exclusions."""
        if not self._charm.unit.is_leader():
            self._charm.peers_data.put(Scope.UNIT, self.RemoveVotingExclusions, True)
            return

        self._charm.peers_data.put(Scope.APP, self.RemoveVotingExclusions, True)

    def set_allocation_exclusions_for_removal(self, unit_name) -> None:
        """Store a unit in the relation data bag, to be removed from the allocation exclusion."""
        if not self._charm.unit.is_leader():
            self._charm.peers_data.put(Scope.UNIT, self.RemoveFromAllocExclusion, unit_name)
            return

        exclusions = set(
            self._charm.peers_data.get(Scope.APP, self.RemoveFromAllocExclusion, "").split(",")
        )
        exclusions.add(unit_name)

        self._charm.peers_data.put(Scope.APP, self.RemoveFromAllocExclusion, ",".join(exclusions))

    def clear_voting_exclusions(self) -> None:
        """Remove the voting exclusions from the peer databag if existing."""
        scope = Scope.UNIT
        if self._charm.unit.is_leader():
            scope = Scope.APP

        self._charm.peers_data.delete(scope, self.RemoveVotingExclusions)

    def clear_allocation_exclusions(self, exclusions: Set[str]) -> None:
        """Remove the allocation exclusions from the peer databag if existing."""
        stored_exclusions = set(
            self._charm.peers_data.get(Scope.APP, self.RemoveFromAllocExclusion, "").split(",")
        )
        exclusions_to_keep = ",".join(stored_exclusions - exclusions)

        scope = Scope.UNIT
        if self._charm.unit.is_leader():
            scope = Scope.APP

        self._charm.peers_data.put(scope, self.RemoveFromAllocExclusion, exclusions_to_keep)


class NodeExclusionOps:
    """Class wrapping both Node Exclusions Operations and Callbacks related to the charm."""

    def __init__(self, distro: OpenSearchDistribution, charm):
        self._distro = distro
        self.in_charm = NodeExclusionInCharmOps(charm)

    def add_if_applies(self, unit_name: str, node_roles: List[str]):
        """Add all (voting + current unit allocation) exclusions when applies."""
        if "cluster_manager" in node_roles:
            try:
                self.add_voting_exclusion(unit_name)
            except OpenSearchError:
                self.in_charm.on_voting_exclusion_add_failed()
                raise

        if "data" in node_roles:
            try:
                self.add_allocation_exclusions(unit_name)
            except OpenSearchError:
                self.in_charm.on_allocation_exclusion_add_failed()
                raise

    def remove_if_applies(self, unit_name: str, host: Optional[str]):
        """Remove all (voting + current unit allocation) exclusions when applies."""
        try:
            # remove the voting exclusions back
            self.remove_voting_exclusions(host)
        except OpenSearchError:
            # no node online, store in the app databag to exclude at a future unit start
            self.in_charm.set_voting_exclusions_for_removal()

        try:
            # remove the exclusion back
            self.remove_allocation_exclusions(unit_name, host)
        except OpenSearchError:
            # no node online, store in the app databag to exclude at a future unit start
            self.in_charm.set_allocation_exclusions_for_removal(unit_name)

    def add_voting_exclusion(self, node_name: str) -> None:
        """Include the current node in the CMs voting exclusions list of nodes."""
        try:
            self._distro.request(
                "POST",
                f"/_cluster/voting_config_exclusions?node_names={node_name}&timeout=1m",
                resp_status_code=True,
            )
        except OpenSearchHttpError as e:
            logger.error(e)
            raise OpenSearchError()

    def add_allocation_exclusions(
        self, exclusions: Union[List[str], Set[str], str], host: Optional[str] = None
    ):
        """Register new allocation exclusions."""
        exclusions = self.normalize_allocation_exclusions(exclusions)
        existing_exclusions = self._fetch_allocation_exclusions(host)
        self._put_allocation_exclusions(existing_exclusions.union(exclusions), host)

    def remove_voting_exclusions(self, host: Optional[str] = None) -> None:
        """Remove the voting exclusions of the whole."""
        # "wait_for_removal" is VERY important, it removes all voting configs immediately
        # and allows any node to return to the voting config in the future
        try:
            self._distro.request(
                "DELETE",
                "/_cluster/voting_config_exclusions?wait_for_removal=false",
                host=host,
                resp_status_code=True,
            )
        except OpenSearchHttpError as e:
            logger.error(e)
            raise OpenSearchError()

        # remove these exclusions from the app data bag if any
        self.in_charm.clear_voting_exclusions()

    def remove_allocation_exclusions(
        self, exclusions: Union[List[str], Set[str], str], host: Optional[str] = None
    ):
        """This removes the allocation exclusions if needed."""
        if exclusions:
            exclusions = self.normalize_allocation_exclusions(exclusions)
            existing_exclusions = self._fetch_allocation_exclusions(host)
            self._put_allocation_exclusions(existing_exclusions - exclusions, host)

        # remove these exclusions from the app data bag if any
        self.in_charm.clear_allocation_exclusions(exclusions)

    def _put_allocation_exclusions(self, exclusions: Set[str], host: Optional[str] = None):
        """Updates the cluster settings with the new allocation exclusions."""
        try:
            response = self._distro.request(
                "PUT",
                "/_cluster/settings",
                {"transient": {"cluster.routing.allocation.exclude._name": ",".join(exclusions)}},
                host=host,
            )
            if not response.get("acknowledged"):
                raise OpenSearchError(f"Allocation exclusion failed for: {exclusions}")
        except OpenSearchHttpError as e:
            logger.error(e)
            raise OpenSearchError()

    def _fetch_allocation_exclusions(self, host: Optional[str]) -> Set[str]:
        """Fetch the registered allocation exclusions."""
        allocation_exclusions = set()
        try:
            resp = self._distro.request("GET", "/_cluster/settings", host=host)
            exclusions = resp["transient"]["cluster"]["routing"]["allocation"]["exclude"]["_name"]
            allocation_exclusions = set(exclusions.split(","))
        except KeyError:
            # no allocation exclusion set
            pass
        finally:
            return allocation_exclusions

    @staticmethod
    def normalize_allocation_exclusions(exclusions: Union[List[str], Set[str], str]) -> Set[str]:
        """Normalize a list of allocation exclusions into a set."""
        if type(exclusions) is list:
            exclusions = set(exclusions)
        elif type(exclusions) is str:
            exclusions = set(exclusions.split(","))

        return exclusions
