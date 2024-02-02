# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Health management."""
import logging
from typing import Dict, Optional

from charms.opensearch.v0.constants_charm import (
    ClusterHealthRed,
    ClusterHealthYellow,
    WaitingForBusyShards,
    WaitingForSpecificBusyShards,
)
from charms.opensearch.v0.helper_charm import Status
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchHAError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.model import BlockedStatus, WaitingStatus
from tenacity import retry, stop_after_attempt, wait_exponential, wait_fixed

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
        status = self.get(
            wait_for_green_first=wait_for_green_first,
            use_localhost=use_localhost,
        )

        if app:
            self._apply_for_app(status)
        else:
            self._apply_for_unit(status)

        return status

    def get(self, wait_for_green_first: bool = False, use_localhost: bool = True) -> str:
        """Fetch the current cluster status."""
        host = self._charm.unit_ip if use_localhost else None

        try:
            response = self._health(wait_for_green=wait_for_green_first, host=host)
        except OpenSearchHttpError:
            return HealthColors.UNKNOWN

        logger.info(f"Health: {response}")
        try:
            status = response["status"].lower()
        except AttributeError as e:
            logger.error(e)  # means the status was reported as an int (i.e: 503)
            return HealthColors.UNKNOWN

        if status != HealthColors.YELLOW:
            return status

        try:
            # we differentiate between a temp yellow (moving shards) and a permanent
            # one (such as: missing replicas)
            shards_by_state = ClusterState.shards_by_state(
                self._opensearch, host=host, alt_hosts=self._charm.alt_hosts
            )
            busy_shards = shards_by_state.get("INITIALIZING", 0) + shards_by_state.get(
                "RELOCATING", 0
            )
            return HealthColors.YELLOW_TEMP if busy_shards > 0 else HealthColors.YELLOW
        except OpenSearchHttpError:
            return HealthColors.UNKNOWN

    @retry(stop=stop_after_attempt(15), wait=wait_fixed(5), reraise=True)
    def wait_for_shards_relocation(self) -> None:
        """Blocking function until the shards relocation completes in the cluster."""
        if self.get(wait_for_green_first=True) != HealthColors.YELLOW_TEMP:
            return

        # we throw an error because various operations should NOT start while data
        # is being relocated. Examples are: simple stop, unit removal, upgrade
        raise OpenSearchHAError("Shards haven't completed relocating.")

    def _apply_for_app(self, status: str) -> None:
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
            self._charm.status.set(BlockedStatus(ClusterHealthRed), app=True)
        elif status == HealthColors.YELLOW_TEMP:
            # health is yellow but temporarily (shards are relocating or initializing)
            self._charm.status.set(WaitingStatus(WaitingForBusyShards), app=True)
        else:
            # health is yellow permanently (some replica shards are unassigned)
            self._charm.status.set(BlockedStatus(ClusterHealthYellow), app=True)

    def _apply_for_unit(self, status: str, host: Optional[str] = None):
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

        message = sorted([f"{key}/{','.join(val)}" for key, val in busy_shards.items()])
        message = WaitingForSpecificBusyShards.format(" - ".join(message))
        self._charm.status.set(WaitingStatus(message))

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def _health(self, host: str, wait_for_green: bool) -> Dict[str, any]:
        """Fetch the cluster health."""
        endpoint = "/_cluster/health"

        timeout = 5
        if wait_for_green:
            endpoint = f"{endpoint}?wait_for_status=green&timeout=1m"
            timeout = 75

        return self._opensearch.request(
            "GET",
            endpoint,
            host=host,
            alt_hosts=self._charm.alt_hosts,
            timeout=timeout,
        )
