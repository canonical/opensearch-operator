# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manages the OpenSearch upgrade process."""


import bisect
import json
import logging

from charms.data_platform_libs.v0.upgrade import (
    ClusterNotReadyError,
    DataUpgrade,
    DependencyModel,
    UpgradeGrantedEvent,
    VersionError,
)
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
    OpenSearchInstallError,
)
from charms.opensearch.v0.opensearch_health import HealthColors
from ops.model import MaintenanceStatus
from pydantic import BaseModel
from typing_extensions import override

logger = logging.getLogger(__name__)


# The unique Charmhub library identifier, never change it
LIBID = "5e3721b8d54b4fe8b3c129b1f029d393"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class OpenSearchDependenciesModel(BaseModel):
    """OpenSearch dependencies model."""

    charm: DependencyModel
    snap: DependencyModel


def get_opensearch_dependencies_model() -> OpenSearchDependenciesModel:
    """Return the OpenSearch dependencies model."""
    with open("src/dependency.json") as dependency_file:
        _deps = json.load(dependency_file)
    return OpenSearchDependenciesModel(**_deps)


class OpenSearchUpgrade(DataUpgrade):
    """OpenSearch upgrade class."""

    def __init__(self, charm, **kwargs) -> None:
        """Initialize the class."""
        super().__init__(charm, **kwargs)
        self.charm = charm
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_upgrade_changed
        )

    def _get_node_roles(self):
        """Get the node roles."""
        try:
            # TODO: FINISH!
            ClusterTopology.nodes_by_role(
                ClusterTopology.nodes(self.opensearch, True, self.alt_hosts)
            )

        except OpenSearchHttpError as e:
            if e.response.status_code == 503:
                raise ClusterNotReadyError("Cluster is not ready")
            raise

    @override
    def build_upgrade_stack(self) -> list[int]:
        """Build the upgrade stack.

        This/leader/primary will be the last.
        """
        upgrade_stack = []
        for unit in self.peer_relation.units:
            bisect.insort(upgrade_stack, int(unit.name.split("/")[1]))

        # TODO: organize the list to have the charm leader and the elected cluster
        # manager as the last ones.
        # Use the _get_node_roles to build a dict in this case
        upgrade_stack.insert(0, self.charm.unit.name.split("/")[1])
        return upgrade_stack

    @override
    def pre_upgrade_check(self) -> None:
        """Run pre-upgrade checks."""
        fail_message = "Pre-upgrade check failed. Cannot upgrade."

        try:
            online_nodes = ClusterTopology.nodes(self.opensearch, True, self.alt_hosts)
            if self.charm.health.apply() != HealthColors.GREEN:
                raise ClusterNotReadyError(
                    message=fail_message,
                    cause=f"Cluster not healthy: expected 'green', but '{self.health.apply()}' found instead",
                    resolution="Ensure cluster is healthy before upgrading",
                )

            if online_nodes < self.charm.app.planned_units():
                # case any not fully online unit is found
                raise ClusterNotReadyError(
                    message=fail_message,
                    cause="Not all units are online",
                    resolution="Ensure all units are online in the cluster",
                )

        except OpenSearchHttpError:
            raise ClusterNotReadyError(
                message=fail_message,
                cause="Cluster is unreachable",
                resolution="Fix the current unit before upgrading",
            )

        if self.charm.unit.is_leader():
            # Disable replication and flush to disk
            # This method only raises ClusterNotReadyError anyways
            self._pre_upgrade_prepare_if_needed()

    def _toggle_shard_replication(self, enable=True):
        fail_message = "Prepare upgrade failed. It is not possible to disable replication."
        try:
            resp = self.opensearch.request(
                "POST",
                "/_cluster/settings",
                json={
                    "persistent": {
                        "cluster.routing.allocation.enable": "primaries" if enable else "all"
                    }
                },
            )
            if not (
                resp["acknowledged"] == "true"
                and resp["persistent"]["cluster"]["routing"]["allocation"]["enable"] == "primaries"
            ):
                # It is the equivalent error
                raise KeyError()
        except KeyError:
            raise ClusterNotReadyError(
                message=fail_message,
                cause="Request to disable primaries failed with unexpected response",
                resolution="Double check the cluster status",
            )

    def _flush_wait_for_ongoing(self):
        fail_message = "Prepare upgrade failed. It is not possible to disable replication."
        try:
            resp = self.opensearch.request(
                "POST",
                "/_flush?wait_for_ongoing",
            )
            if not (
                resp["_shards"]["total"] == resp["_shards"]["successful"]
                and resp["_shards"]["failed"] == 0
            ):
                # It is the equivalent error
                raise KeyError()
        except KeyError:
            raise ClusterNotReadyError(
                message=fail_message,
                cause="Request to disable primaries failed with unexpected response",
                resolution="Double check the cluster status",
            )

    def _pre_upgrade_prepare_if_needed(self):
        """Disables the replication and flushes the cluster."""
        fail_message = "Prepare upgrade failed. Cannot upgrade."
        try:
            self._toggle_shard_replication(enable=False)
            self._flush_wait_for_ongoing()
        except OpenSearchHttpError:
            raise ClusterNotReadyError(
                message=fail_message,
                cause=f"{self.charm.unit.name} is unreachable",
                resolution=f"Ensure {self.charm.unit.name} is reachable",
            )

    @override
    def _on_upgrade_granted(self, event: UpgradeGrantedEvent) -> None:  # noqa: C901
        """Handle the upgrade granted event."""
        try:
            # If this is the first, unit, execute the pre-upgrade steps
            if self.idle:
                self._pre_upgrade_prepare_if_needed()

            self.charm.unit.status = MaintenanceStatus("stopping services..")
            self.charm.opensearch._stop_opensearch()

            self.charm.unit.status = MaintenanceStatus("upgrading opensearch...")
            if not self.charm.opensearch.install():
                logger.error("Failed to install opensearch application")
                self.set_unit_failed()
                return
            self.charm.unit.status = MaintenanceStatus("check if upgrade is possible")
            self.charm.opensearch._stop_opensearch()
        except (ClusterNotReadyError, VersionError, OpenSearchInstallError) as e:
            if isinstance(e, ClusterNotReadyError):
                logger.exception("Cluster is not ready for upgrade")
            elif isinstance(e, VersionError):
                logger.exception("Failed to upgrade OpenSearch")
            else:
                logger.exception("Failed to stop/start MySQL server")
            self.set_unit_failed()
            return

        # Check the unit is running
        try:
            # Only asking the local node
            online_nodes = ClusterTopology.nodes(self.opensearch, True, None)
            if not online_nodes or online_nodes != self.charm.app.planned_units():
                raise ClusterNotReadyError(
                    message="Upgrade failed. Cluster is not ready",
                    cause="Not all units are online",
                    resolution="Ensure all units are online in the cluster",
                )
            # TODO: check node's indices and shards health

        except OpenSearchError:
            logger.exception("Failed to check the new node")
            self.set_unit_failed()
            return

        if self.charm.unit.is_leader():
            self.charm.on[self.relation_name].relation_changed.emit(
                self.model.get_relation(self.relation_name)
            )

    def _on_upgrade_changed(self, event) -> None:
        """Handle the upgrade changed event."""
        if not self.upgrade.idle:
            event.defer()
            return
        self._toggle_shard_replication(enable=True)

    @override
    def log_rollback_instructions(self) -> None:
        """Log rollback instructions."""
        logger.critical(
            "\n".join(
                (
                    "Upgrade failed, follow the instructions below to rollback:",
                    "    1. Re-run `pre-upgrade-check` action on the leader unit to enter 'recovery' state",
                    "    2. Run `juju refresh` to the previously deployed charm revision or local charm file",
                )
            )
        )
