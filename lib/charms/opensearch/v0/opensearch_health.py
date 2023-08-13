# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Health management."""
import logging
from typing import Dict, Optional

from charms.opensearch.v0.constants_charm import (
    ClusterHealthRed,
    ClusterHealthYellow,
    Scope,
    WaitingForBusyShards,
    WaitingForSpecificBusyShards,
)
from charms.opensearch.v0.helper_charm import Status
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from ops.model import BlockedStatus, WaitingStatus

# The unique Charmhub library identifier, never change it
LIBID = "93d2c27f38974a59b3bbe39fb27ac98d"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class HealthColors:
    """Colors the clusters or a unit may have depending on their health."""

    GREEN = "green"
    YELLOW = "yellow"
    YELLOW_TEMP = "yellow-temp"
    RED = "red"
    UNKNOWN = "unknown"


class OpenSearchHealth:
    """Class for managing OpenSearch statuses."""

    def __init__(self, charm):
        self._charm = charm
        self._opensearch = self._charm.opensearch

    def apply(
        self,
        wait_for_green_first: bool = False,
        use_localhost: bool = True,
        app: bool = True,
    ) -> str:
        """Fetch cluster health and set it on the app status."""
        try:
            host = self._charm.unit_ip if use_localhost else None
            status = self._fetch_status(host, wait_for_green_first)
            if not status:
                return HealthColors.UNKNOWN

            if app:
                self.apply_for_app(status)
            else:
                self.apply_for_unit(status)

            return status
        except OpenSearchHttpError:
            return HealthColors.UNKNOWN

    def apply_for_app(self, status: str) -> None:
        """Cluster wide / app status."""
        if not self._charm.unit.is_leader():
            # this is needed in case the leader is in an error state and doesn't
            # report the status itself
            self._charm.peers_data.put(Scope.UNIT, "health", status)
            return

        if status == HealthColors.GREEN:
            # health green: cluster healthy
            self._charm.status.clear(ClusterHealthRed, app=True)
            self._charm.status.clear(ClusterHealthYellow, app=True)
            self._charm.status.clear(WaitingForBusyShards, app=True)
        elif status == HealthColors.RED:
            # health RED: some primary shards are unassigned
            self._charm.app.status = BlockedStatus(ClusterHealthRed)
        elif status == HealthColors.YELLOW_TEMP:
            # health is yellow but temporarily (shards are relocating or initializing)
            self._charm.app.status = WaitingStatus(WaitingForBusyShards)
        else:
            # health is yellow permanently (some replica shards are unassigned)
            self._charm.app.status = BlockedStatus(ClusterHealthYellow)

    def apply_for_unit(self, status: str, host: Optional[str] = None):
        """Apply the health status on the current unit."""
        if status != HealthColors.YELLOW_TEMP:
            self._charm.status.clear(
                WaitingForSpecificBusyShards, pattern=Status.CheckPattern.Interpolated
            )
            return

        busy_shards = ClusterState.busy_shards_by_unit(
            self._opensearch, host=host, alt_hosts=self._charm.alt_hosts
        )
        if not busy_shards:
            self._charm.status.clear(
                WaitingForSpecificBusyShards, pattern=Status.CheckPattern.Interpolated
            )
            return

        message = WaitingForSpecificBusyShards.format(
            " - ".join([f"{key}/{','.join(val)}" for key, val in busy_shards.items()])
        )
        self._charm.unit.status = WaitingStatus(message)

    def _fetch_status(self, host: Optional[str] = None, wait_for_green_first: bool = False):
        """Fetch the current cluster status."""
        response: Optional[Dict[str, any]] = None
        if wait_for_green_first:
            try:
                response = ClusterState.health(
                    self._opensearch,
                    True,
                    host=host,
                    alt_hosts=self._charm.alt_hosts,
                )
            except OpenSearchHttpError:
                # it timed out, settle with current status, fetched next without the 1min wait
                pass

        if not response:
            response = ClusterState.health(
                self._opensearch,
                False,
                host=host,
                alt_hosts=self._charm.alt_hosts,
            )

        if not response:
            return None

        logger.info(f"Health: {response['status']}")
        status = response["status"].lower()
        if status != HealthColors.YELLOW:
            return status

        # we differentiate between a temp yellow (moving shards) and perm one (missing replicas)
        shards_by_state = ClusterState.shards_by_state(
            self._opensearch, host=host, alt_hosts=self._charm.alt_hosts
        )
        busy_shards = shards_by_state.get("INITIALIZING", 0) + shards_by_state.get("RELOCATING", 0)
        return HealthColors.YELLOW_TEMP if busy_shards > 0 else HealthColors.YELLOW
