# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for OpenSearch node exclusions management."""
import logging
from functools import cached_property
from typing import List, Optional, Set

from charms.opensearch.v0.helper_charm import all_units, format_unit_name
from charms.opensearch.v0.models import Node, PeerClusterApp
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope

# The unique Charmhub library identifier, never change it
LIBID = "51c1ac864e9a4d12b1d1ef27c0ff2e50"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class OpenSearchExclusionsException(OpenSearchError):
    """Exception class for all Voting/Allocation exclusions related exceptions."""


ALLOCS_TO_DELETE = "allocation-exclusions-to-delete"
VOTING_TO_DELETE = "delete-voting-exclusions"


class OpenSearchExclusions:
    """Exclusions related operations, important to reason as exclusions, NOT additions."""

    def __init__(self, charm):
        self._charm = charm
        self._opensearch = self._charm.opensearch
        self._scope = Scope.APP if self._charm.unit.is_leader() else Scope.UNIT

    def add_to_cleanup_list(self, unit_name: str) -> None:
        """Add Voting and alloc exclusions for a target unit.

        This method is just a clean-up-later routine. We (re)add the unit to the exclusions and,
        hence, the leader of this app will be aware of this unit's removal and log it into its
        app-level peer data.
        """
        for lst in [ALLOCS_TO_DELETE, VOTING_TO_DELETE]:
            # Load the content of the list, avoiding '' entries
            current_set = set(
                filter(None, self._charm.peers_data.get(self._scope, lst, "").split(","))
            )
            current_set = current_set.union({unit_name})

            self._charm.peers_data.put(self._scope, lst, ",".join(current_set))

    def add_current(
        self, voting: bool = True, allocation: bool = True, raise_error: bool = False
    ) -> None:
        """Add voting and alloc exclusions."""
        if voting and (self._node.is_cm_eligible() or self._node.is_voting_only()):
            if not self._add_voting():
                logger.error(f"Failed to add voting exclusion: {self._node.name}.")
                if raise_error:
                    raise OpenSearchExclusionsException("Failed to add voting exclusion.")

        if allocation and self._node.is_data():
            if not self._add_allocations():
                logger.error(f"Failed to add shard allocation exclusion: {self._node.name}.")
                if raise_error:
                    raise OpenSearchExclusionsException("Failed to add allocation exclusion.")

    def delete_current(
        self, voting: bool = True, allocation: bool = True, raise_error: bool = False
    ) -> None:
        """Delete voting and alloc exclusions."""
        if voting and (self._node.is_cm_eligible() or self._node.is_voting_only()):
            if not self._delete_voting({self._node.name}):
                logger.error(f"Failed to delete voting exclusion: {self._node.name}.")
                if raise_error:
                    raise OpenSearchExclusionsException("Failed to delete voting exclusion.")

        if allocation and self._node.is_data():
            if not self._delete_allocations():
                logger.error(f"Failed to delete shard allocation exclusion: {self._node.name}.")
                # Load the content of the list, avoiding '' entries
                current_allocations = set(
                    filter(
                        None,
                        self._charm.peers_data.get(self._scope, ALLOCS_TO_DELETE, "").split(","),
                    )
                )
                current_allocations.add(self._node.name)

                self._charm.peers_data.put(
                    self._scope, ALLOCS_TO_DELETE, ",".join(current_allocations)
                )
                if raise_error:
                    raise OpenSearchExclusionsException("Failed to delete allocation exclusion.")

    def cleanup(self) -> None:
        """Delete all exclusions that failed to be deleted."""
        self._delete_voting(
            self._units_to_cleanup(
                list(
                    filter(
                        None,
                        self._charm.peers_data.get(self._scope, VOTING_TO_DELETE, "").split(","),
                    )
                )
            )
        )

        allocations_to_cleanup = list(
            filter(None, self._charm.peers_data.get(self._scope, ALLOCS_TO_DELETE, "").split(","))
        )
        if allocations_to_cleanup and self._delete_allocations(allocations_to_cleanup):
            self._charm.peers_data.delete(self._scope, ALLOCS_TO_DELETE)

    def _units_to_cleanup(self, removable: List[str]) -> Optional[Set[str]]:
        """Deletes all units that have left the cluster via Juju.

        This method ensures we keep a small list of voting exclusions at all times.
        """
        if (
            not (deployment_desc := self._charm.opensearch_peer_cm.deployment_desc())
            or not removable
        ):
            return set()

        if self._charm.opensearch_peer_cm.is_provider(typ="main") and (
            apps_in_fleet := self._charm.peers_data.get_object(Scope.APP, "cluster_fleet_apps")
        ):
            apps_in_fleet = [PeerClusterApp.from_dict(app) for app in apps_in_fleet.values()]
            units = {
                format_unit_name(u, p_cluster_app.app)
                for p_cluster_app in apps_in_fleet
                for u in p_cluster_app.units
            }
        else:
            units = {format_unit_name(u, deployment_desc.app) for u in all_units(self._charm)}

        # Now, we need to remove the units that were marked for deletion and are not in the
        # cluster anymore.
        to_remove = []
        for node in removable:
            if node not in units:
                # Unit still exists
                to_remove.append(node)
        return set(to_remove)

    def _get_voting_to_delete(self) -> Set[str]:
        """Return the list of voting exclusions to delete."""
        return set(
            filter(
                None,
                self._charm.peers_data.get(self._scope, VOTING_TO_DELETE, "").split(","),
            )
        )

    def _add_voting(self, exclusions: Optional[Set[str]] = None) -> bool:
        """Include the current node in the CMs voting exclusions list of nodes."""
        try:
            to_add = exclusions or {self._node.name}
            response = self._opensearch.request(
                "POST",
                f"/_cluster/voting_config_exclusions?node_names={','.join(to_add)}&timeout=1m",
                alt_hosts=self._charm.alt_hosts,
                resp_status_code=True,
                retries=3,
            )
            logger.debug("Added voting, response: %s", response)

            self._charm.peers_data.put(
                self._scope,
                VOTING_TO_DELETE,
                ",".join(to_add.union(self._get_voting_to_delete())),
            )
            # The voting excl. API returns a status only
            return response < 400
        except OpenSearchHttpError:
            return False

    def _delete_voting(self, exclusions: Set[str]) -> bool:
        """Remove all voting exclusions and then re-adds the subset that should stay.

        The API does not allow to remove a subset of the voting exclusions, at once.
        """
        current_excl = self._fetch_voting()
        logger.debug("Current voting exclusions: %s", current_excl)
        if not current_excl:
            to_stay = None
        else:
            to_stay = current_excl - exclusions
        if current_excl == to_stay:
            # Nothing to do
            logger.debug("No voting exclusions to delete, current set is %s", to_stay)
            return True

        # "wait_for_removal" is VERY important, it removes all voting configs immediately
        # and allows any node to return to the voting config in the future
        try:
            response = self._opensearch.request(
                "DELETE",
                "/_cluster/voting_config_exclusions?wait_for_removal=false",
                alt_hosts=self._charm.alt_hosts,
                resp_status_code=True,
            )
            if response >= 400:
                logger.debug("Failed to remove voting exclusions, response %s", response)
                return False

            logger.debug("Removed voting for:  %s", exclusions)
            if to_stay:
                # Now, we register the units that should stay
                response = self._opensearch.request(
                    "POST",
                    f"/_cluster/voting_config_exclusions?node_names={','.join(sorted(to_stay))}&timeout=1m",
                    alt_hosts=self._charm.alt_hosts,
                    resp_status_code=True,
                    retries=3,
                )
                if response >= 400:
                    logger.debug("Failed to remove voting exclusions, response %s", response)
                    return False

            # Finally, we clean up the VOTING_TO_DELETE
            self._charm.peers_data.put(
                self._scope,
                VOTING_TO_DELETE,
                ",".join(self._get_voting_to_delete() - exclusions),
            )
            return response < 400
        except OpenSearchHttpError:
            return False

    def _fetch_voting(self) -> Set[str]:
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

    def _add_allocations(
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

    def _delete_allocations(self, allocs: Optional[List[str]] = None) -> bool:
        """This removes the allocation exclusions if needed."""
        try:
            existing = self._fetch_allocations()
            to_remove = set(allocs if allocs is not None else [self._node.name])
            res = self._add_allocations(existing - to_remove, override=True)
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
