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
from charms.opensearch.v0.helper_charm import Status
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.models import StartMode
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.model import BlockedStatus, MaintenanceStatus, WaitingStatus

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
        try:
            host = self._charm.unit_ip if use_localhost else None
            status = self._fetch_status(host, wait_for_green_first)
            if not status:
                return HealthColors.UNKNOWN

            # the health depends on data nodes, for large deployments: an ML cluster
            # may not be concerned about reporting or relying on the health of the
            # data nodes in other clusters. We should therefore get this info from
            # the deployment descriptor which has an overview of all the cluster
            if not (deployment_desc := self._charm.opensearch_peer_cm.deployment_desc()):
                return HealthColors.UNKNOWN

            # compute health only in clusters where data nodes exist
            compute_health = (
                deployment_desc.start == StartMode.WITH_GENERATED_ROLES
                or "data" in deployment_desc.config.roles
            )
            if not compute_health:
                return HealthColors.IGNORE

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
            self._charm.status.set(BlockedStatus(ClusterHealthRed), app=True)
        elif status == HealthColors.YELLOW_TEMP:
            # health is yellow but temporarily (shards are relocating or initializing)
            self._charm.status.set(MaintenanceStatus(WaitingForBusyShards), app=True)
        else:
            # health is yellow permanently (some replica shards are unassigned)
            self._charm.status.set(BlockedStatus(ClusterHealthYellow), app=True)

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

        message = sorted([f"{key}/{','.join(val)}" for key, val in busy_shards.items()])
        message = WaitingForSpecificBusyShards.format(" - ".join(message))
        self._charm.status.set(WaitingStatus(message))

    def _fetch_status(self, host: Optional[str] = None, wait_for_green_first: bool = False):
        """Fetch the current cluster status."""
        response: Optional[Dict[str, any]] = None
        if wait_for_green_first:
            try:
                response = ClusterState.health(
                    self._opensearch,
                    wait_for_green=True,
                    host=host,
                    alt_hosts=self._charm.alt_hosts,
                )
            except OpenSearchHttpError:
                # it timed out, settle with current status, fetched next without
                # the 1min wait
                pass

        if not response:
            response = ClusterState.health(
                self._opensearch,
                wait_for_green=False,
                host=host,
                alt_hosts=self._charm.alt_hosts,
            )

        if not response:
            return None

        logger.info(f"Health: {response}")
        try:
            status = response["status"].lower()
        except AttributeError as e:
            logger.error(e)  # means the status was reported as an int (i.e: 503)
            return None

        if status != HealthColors.YELLOW:
            return status

        # we differentiate between a temp yellow (moving shards) and a permanent
        # one (such as: missing replicas)
        if response["initializing_shards"] > 0 or response["relocating_shards"] > 0:
            return HealthColors.YELLOW_TEMP
        return HealthColors.YELLOW
