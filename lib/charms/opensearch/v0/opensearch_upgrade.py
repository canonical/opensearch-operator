# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manages the OpenSearch upgrade process."""


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
    OpenSearchStartTimeoutError,
)
from charms.opensearch.v0.opensearch_health import HealthColors
from ops.framework import EventBase
from ops.model import ActiveStatus, MaintenanceStatus
from pydantic import BaseModel
from tenacity import retry, stop_after_attempt, wait_fixed
from typing_extensions import override

logger = logging.getLogger(__name__)


# The unique Charmhub library identifier, never change it
LIBID = "5e3721b8d54b4fe8b3c129b1f029d393"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class PostUpgrade(EventBase):
    """Marks the end of an upgrade.

    Originally, it was tried to use "upgrade-changed" event for this task, but
    the "upgrade-changed" event runs with or without upgrades being granted.
    They also run at the start of the deployment.

    This event is emitted when the upgrade is finished on the leader, and deferred
    until the upgrade is done.
    """

    pass


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

        self.charm.on.define_event("{}_post_upgrade".format(self.relation_name), PostUpgrade)
        self.framework.observe(charm.on[self.relation_name].post_upgrade, self._on_post_upgrade)

        self.charm = charm
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_upgrade_changed
        )

    @override
    def build_upgrade_stack(self) -> list[int]:
        """Build the upgrade stack.

        The upgrade stack is built in a way the upgrade order is:
        - non-manager nodes
        - manager eligible nodes
        - elected manager
        """
        upgrade_stack = []
        nodes = ClusterTopology.nodes(self.charm.opensearch, True, self.charm.alt_hosts)
        units = set(self.peer_relation.units)
        units.add(self.charm.unit)

        if len(units) != len(nodes):
            raise ClusterNotReadyError(
                message="Upgrade failed. Cluster is not ready",
                cause="Not all units are online",
                resolution="Ensure all units are online in the cluster",
            )

        try:
            elected_manager = None
            for node in nodes:
                if node.elected_manager:
                    elected_manager = node.name.split("-")[-1]
                    # Insert the elected manager as the last one
                    continue
                if "cluster_manager" not in node.roles:
                    # Insert the non-manager node at the beginning of the queue
                    upgrade_stack.append(node.name.split("-")[1])
                else:
                    # Insert the eligible manager as the last ones.
                    upgrade_stack.insert(0, node.name.split("-")[1])

            if not elected_manager:
                raise ClusterNotReadyError(
                    message="Upgrade failed. Cluster is not ready",
                    cause="Cluster does not have elected a manager",
                    resolution="Ensure a manager is elected in the cluster",
                )

            # the elected manager is the last unit to upgrade.
            upgrade_stack.insert(0, elected_manager)
        except OpenSearchHttpError:
            raise ClusterNotReadyError(
                message="Upgrade failed. Cluster is not ready",
                cause="Cluster is unreachable",
                resolution="Ensure the network to the cluster is fixed",
            )

        return upgrade_stack

    @override
    def pre_upgrade_check(self) -> None:
        """Run pre-upgrade checks."""
        fail_message = "Pre-upgrade check failed. Cannot upgrade."

        try:
            online_nodes = ClusterTopology.nodes(self.charm.opensearch, True, self.charm.alt_hosts)
            if self.charm.health.apply() != HealthColors.GREEN:
                raise ClusterNotReadyError(
                    message=fail_message,
                    cause=f"Cluster not healthy: expected 'green', but '{self.health.apply()}' found instead",
                    resolution="Ensure cluster is healthy before upgrading",
                )

            if len(online_nodes) < self.charm.app.planned_units():
                # case any not fully online unit is found
                raise ClusterNotReadyError(
                    message=fail_message,
                    cause="Not all units are online",
                    resolution="Ensure all units are online in the cluster",
                )

            if self.charm.check_if_starting():
                raise ClusterNotReadyError(
                    message=fail_message,
                    cause="Cluster is starting",
                    resolution="Ensure cluster has finished its start cycle before proceeding",
                )

            if not self.charm.backup.is_idle():
                raise ClusterNotReadyError(
                    message=fail_message,
                    cause="Backup is in progress",
                    resolution="Ensure backup is completed before upgrading",
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
            resp = self.charm.opensearch.request(
                "PUT",
                "/_cluster/settings",
                payload={
                    "persistent": {
                        "cluster.routing.allocation.enable": "all" if enable else "primaries"
                    }
                },
            )
            if not (
                resp["acknowledged"]
                and resp["persistent"]["cluster"]["routing"]["allocation"]["enable"] == "all"
                if enable
                else "primaries"
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
            resp = self.charm.opensearch.request(
                "POST",
                "/_flush?wait_if_ongoing",
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
            self._flush_wait_for_ongoing()
            self._toggle_shard_replication(enable=False)
        except OpenSearchHttpError:
            raise ClusterNotReadyError(
                message=fail_message,
                cause=f"{self.charm.unit.name} is unreachable",
                resolution=f"Ensure {self.charm.unit.name} is reachable",
            )

    @retry(reraise=True, stop=stop_after_attempt(5), wait=wait_fixed(15))
    def _execute_upgrade(self):
        # If this is the first, unit, execute the pre-upgrade steps
        self.charm.unit.status = MaintenanceStatus("stopping services..")
        self.charm._stop_opensearch()

        self.charm.unit.status = MaintenanceStatus("upgrading opensearch...")
        self.charm.opensearch.install()
        if not self.charm.opensearch.present:
            logger.error("Failed to install opensearch application")
            raise OpenSearchInstallError()

    @retry(reraise=True, stop=stop_after_attempt(5), wait=wait_fixed(15))
    def _enable_service(self):
        self.charm.unit.status = MaintenanceStatus("starting opensearch...")
        # Remove the exclusions that could not be removed when no units were online
        # start the opensearch service
        self.charm.opensearch._start_service()
        if not self.charm.opensearch.is_node_up():
            raise OpenSearchStartTimeoutError()
        self.charm.opensearch_exclusions.delete_current()

    @retry(reraise=True, stop=stop_after_attempt(5), wait=wait_fixed(15))
    def _ensure_post_upgrade_checks(self):
        # Only asking the local node
        online_nodes = ClusterTopology.nodes(self.charm.opensearch, True, None)
        if not online_nodes or len(online_nodes) != self.charm.app.planned_units():
            raise ClusterNotReadyError(
                message="Post upgrade check failed. Cluster is not ready",
                cause="Not all units are online",
                resolution="Ensure all units are online in the cluster",
            )
        # TODO: check node's indices and shards health

    @override
    def _on_upgrade_granted(self, event: UpgradeGrantedEvent) -> None:  # noqa: C901
        """Handle the upgrade granted event."""
        try:
            self._execute_upgrade()
            self._enable_service()
        except (
            ClusterNotReadyError,
            VersionError,
            OpenSearchError,
        ) as e:
            if isinstance(e, ClusterNotReadyError):
                logger.exception("Cluster is not ready for upgrade")
            elif isinstance(e, VersionError):
                logger.exception("Failed to upgrade OpenSearch")
            elif isinstance(e, OpenSearchInstallError):
                logger.exception("Failed to install OpenSearch")
            else:
                logger.exception("Failed to stop/start MySQL server")
            self.set_unit_failed()
            return

        # Check the unit is running post-upgrade
        try:
            self._ensure_post_upgrade_checks()
        except (ClusterNotReadyError, OpenSearchError):
            logger.exception("Cluster is not recovered after upgrade")
            self.set_unit_failed()
            return

        if self.charm.unit.is_leader():
            # As documented in the upgrades lib
            self.charm.on[self.relation_name].relation_changed.emit(
                self.model.get_relation(self.relation_name)
            )
        # All units emit this event
        # Avoids the condition where the leader goes away before we can
        # actually execute this task
        self.charm.on[self.relation_name].post_upgrade.emit()

        self.set_unit_completed()
        self.charm.unit.status = ActiveStatus()

    def _on_post_upgrade(self, event) -> None:
        if not self.idle:
            event.defer()
            return
        try:
            if self.charm.unit.is_leader():
                self._toggle_shard_replication(enable=True)
        except OpenSearchError:
            event.defer()
            return

    def _on_upgrade_changed(self, event) -> None:
        """Handle the upgrade changed event."""
        pass

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
