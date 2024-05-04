# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Health management."""
import logging
from typing import Dict, Optional

from charms.opensearch.v0.constants_charm import (
    ClusterHealthRed,
    ClusterHealthRedUpgrade,
    ClusterHealthYellow,
    WaitingForBusyShards,
    WaitingForSpecificBusyShards,
)
from charms.opensearch.v0.helper_charm import Status, trigger_peer_rel_changed
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.models import StartMode
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchHAError,
    OpenSearchHttpError,
)
from ops.model import BlockedStatus, MaintenanceStatus, WaitingStatus
from tenacity import retry, stop_after_attempt, wait_fixed

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
    IGNORE = "ignore"


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
        logger.info(f"Current health of cluster: {status}")

        if app:
            self._apply_for_app(status)
        else:
            self._apply_for_unit(status)

        return status

    def get(  # noqa: C901
        self,
        wait_for_green_first: bool = False,
        use_localhost: bool = True,
        local_app_only: bool = True,
    ) -> str:
        """Fetch the current cluster status."""
        if not (deployment_desc := self._charm.opensearch_peer_cm.deployment_desc()):
            return HealthColors.UNKNOWN

        # the health depends on data nodes, for large deployments: an ML cluster
        # may not be concerned about reporting or relying on the health of the
        # data nodes in other clusters. We should therefore get this info from
        # the deployment descriptor which has an overview of all the cluster.
        # compute health only in clusters where data nodes exist
        compute_health = (
            deployment_desc.start == StartMode.WITH_GENERATED_ROLES
            or "data" in deployment_desc.config.roles
            or not local_app_only
        )
        if not compute_health:
            return HealthColors.IGNORE

        host = self._charm.unit_ip if use_localhost else None
        response = self._health(host, wait_for_green_first)
        if wait_for_green_first and not response:
            response = self._health(host, False)

        if not response:
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
            logger.debug(
                f"\n\nHealth: {status} -- Shards: {ClusterState.shards(self._opensearch, host)}\n\n"
            )
        except OpenSearchHttpError:
            pass

        # we differentiate between a temp yellow (moving shards) and a permanent
        # one (such as: missing replicas)
        if response["initializing_shards"] > 0 or response["relocating_shards"] > 0:
            return HealthColors.YELLOW_TEMP
        return HealthColors.YELLOW

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
            trigger_peer_rel_changed(self._charm, on_other_units=True)
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
            self._charm.status.set(MaintenanceStatus(WaitingForBusyShards), app=True)
        elif status == HealthColors.YELLOW:
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

    def apply_for_unit_during_upgrade(self, status: str) -> None:
        """Set cluster wide status on unit during upgrade

        During upgrade, app status is used to show upgrade progress
        And, unit checking cluster wide status may not be leader
        """
        if status in (HealthColors.GREEN, HealthColors.YELLOW):
            # health green or yellow: cluster healthy
            # TODO future improvement:
            # https://github.com/canonical/opensearch-operator/issues/268
            self._charm.status.clear(ClusterHealthRedUpgrade)
            self._charm.status.clear(WaitingForBusyShards)
        elif status == HealthColors.RED:
            # health RED: some primary shards are unassigned
            self._charm.status.set(BlockedStatus(ClusterHealthRedUpgrade))
        elif status == HealthColors.YELLOW_TEMP:
            # health is yellow but temporarily (shards are relocating or initializing)
            self._charm.status.set(MaintenanceStatus(WaitingForBusyShards))

    def _health(self, host: str, wait_for_green: bool) -> Optional[Dict[str, any]]:
        """Fetch the cluster health."""
        endpoint = "/_cluster/health"

        timeout = 5
        if wait_for_green:
            endpoint = f"{endpoint}?wait_for_status=green&timeout=1m"
            timeout = 61

        try:
            return self._opensearch.request(
                "GET",
                endpoint,
                host=host,
                alt_hosts=self._charm.alt_hosts,
                timeout=timeout,
                retries=3,
            )
        except OpenSearchHttpError:
            return None
