# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Snapshots."""

import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Optional, Tuple

from charms.data_platform_libs.v0.azure_storage import (
    AzureStorageRequires,
)
from charms.data_platform_libs.v0.azure_storage import (
    StorageConnectionInfoChangedEvent as StorageConnectionInfoChangedEventAzure,
)
from charms.data_platform_libs.v0.azure_storage import (
    StorageConnectionInfoGoneEvent as StorageConnectionInfoGoneEventAzure,
)
from charms.data_platform_libs.v0.data_interfaces import Scope
from charms.data_platform_libs.v0.s3 import (
    S3Requires,
)
from charms.data_platform_libs.v0.s3 import (
    StorageConnectionInfoChangedEvent as StorageConnectionInfoChangedEventS3,
)
from charms.data_platform_libs.v0.s3 import (
    StorageConnectionInfoGoneEvent as StorageConnectionInfoGoneEventS3,
)
from charms.opensearch.v0.constants_charm import (
    AZURE_RELATION,
    GCS_RELATION,
    OPENSEARCH_BACKUP_ID_FORMAT,
    S3_RELATION,
    BackupInProgress,
    PeerClusterRelationName,
    RestoreInProgress,
)
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.helper_security import list_cas, remove_ca, store_ca
from charms.opensearch.v0.models import (
    AzureRelData,
    DeploymentType,
    GcsRelData,
    ObjectStorageConfig,
    S3RelData,
)
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_locking import OpenSearchNodeLock
from ops import (
    ActionEvent,
    BlockedStatus,
    MaintenanceStatus,
    Object,
    Relation,
    Secret,
)
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed

# The unique Charmhub library identifier, never change it
LIBID = "89db18e639c64a6ea223c63172c04dc6."

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm


# Object storage types
ObjectStorageType = Literal[
    "s3", "azure", "gcs", "s3-pcluster", "azure-pcluster", "gcs-pcluster", "conflict"
]

# OpenSearch Backups
S3_REPOSITORY = "s3-repository"
AZURE_REPOSITORY = "azure-repository"
GCS_REPOSITORY = "gcs-repository"
OS_PEER_KEY_TYPE = "snapshot-object-storage-type"
OS_PEER_KEY_SECRET = "snapshot-object-storage-secret"
OS_PEER_KEY_REV = "snapshot-object-storage-data-revision"


# System indices that should not be snapshotted
SYSTEM_INDICES = {
    ".opendistro_security",
    OpenSearchNodeLock.OPENSEARCH_INDEX,
}


class OpenSearchSnapshotsEvents(Object):
    """Events class for Backups (snapshots)."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, key="backups")
        self.charm = charm

        # requirers
        self.s3_requirer = S3Requires(charm, S3_RELATION)
        self.azure_requirer = AzureStorageRequires(charm, AZURE_RELATION)
        self.gcs_requirer = AzureStorageRequires(charm, GCS_RELATION)

        # simple deployments or main orchestrator
        self.framework.observe(
            self.s3_requirer.on.s3_connection_info_changed, self._on_s3_credentials_changed
        )
        self.framework.observe(
            self.s3_requirer.on.s3_connection_info_gone, self._on_s3_credentials_gone
        )
        self.framework.observe(
            self.azure_requirer.on.storage_connection_info_changed,
            self._on_azure_credentials_changed,
        )
        self.framework.observe(
            self.azure_requirer.on.storage_connection_info_gone, self._on_azure_credentials_gone
        )

        # large deployments with non-main orchestrator
        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_changed,
            self._on_peer_clusters_relation_changed_for_snapshots,
        )
        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_departed,
            self._on_peer_clusters_relation_departed_for_snapshots,
        )

        # actions
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_action)

    def _on_s3_credentials_changed(self, event: StorageConnectionInfoChangedEventS3) -> None:
        """Handler for s3 credentials changed event."""
        object_storage_type = self.object_storage_type or "s3"

        if object_storage_type == "conflict":
            self.charm.status.set(BlockedStatus("More than 1 object storage relation"))
            event.defer()
            return

        # handle case where this was deferred in the above case, then the s3 relation was severed
        if (
            object_storage_type != "s3"
            or not self.object_storage_config.s3
            or not self.object_storage_config.s3.credentials
        ):
            logger.warning("No S3 object storage configuration.")
            return
        logger.info("S3 object storage configuration: %s", self.object_storage_config.s3)

        # publish secret + bump revision to peer-clusters
        payload = _make_os_secret_payload_s3(self.object_storage_config.s3)
        _publish_to_peers_with_secret(self.charm, "s3", payload)

        # 2) apply locally (leader does cluster-level config)
        self.charm.keystore_manager.put_entries(
            {
                "s3.client.default.access_key": self.object_storage_config.s3.credentials.access_key,
                "s3.client.default.secret_key": self.object_storage_config.s3.credentials.secret_key,
            }
        )
        self.charm.keystore_manager.reload()

        if self.charm.snapshots_manager.requires_custom_s3_ca(
            object_storage_type, self.object_storage_config
        ):
            self.charm.snapshots_manager.store_s3_ca(self.object_storage_config.s3.tls_ca_chain)
            logger.info("S3 CA is stored.")
        else:
            # If a custom CA is currently stored but no longer required, drop it
            if self.charm.snapshots_manager.is_custom_s3_ca_stored():
                self.charm.snapshots_manager.store_s3_ca(None)
                logger.info("S3 CA is deleted.")

        need_restart = False
        try:
            need_restart = self.charm.snapshots_manager.should_restart_for_full_setup(
                object_storage_type="s3",
                object_storage_config=self.object_storage_config,
            )
            logger.info("service should be restarted")
        except OpenSearchHttpError as e:
            logger.warning("Skip restart precheck (OpenSearch not ready?): %s", e)
            need_restart = False

        if need_restart:
            if self.charm.request_opensearch_restart(reason="apply new object storage CA"):
                # defer only when we actually emitted the restart
                event.defer()
                return
        self._ensure_repository(object_storage_type, self.object_storage_config)

    def _on_s3_credentials_gone(self, event: StorageConnectionInfoGoneEventS3) -> None:
        """Handler for s3 credentials gone event."""
        if self.object_storage_type == "conflict":
            return

        keystore_entries = ["s3.client.default.access_key", "s3.client.default.secret_key"]
        if not self._cleanup(object_storage_type="s3", keystore_entries=keystore_entries):
            event.defer()
            return

        if self.charm.snapshots_manager.is_custom_s3_ca_stored():
            self.charm.snapshots_manager.store_s3_ca(None)
            self.charm.request_opensearch_restart(reason="clean up the object storage CA")

        # publish deletion
        _clear_from_peers_and_delete_secret(self.charm)

    def _on_azure_credentials_changed(self, event: StorageConnectionInfoChangedEventAzure) -> None:
        """Handler for azure credentials changed event."""
        object_storage_type = self.object_storage_type or "azure"

        if object_storage_type == "conflict":
            self.charm.status.set(BlockedStatus("More than 1 object storage relation."))
            event.defer()
            return

        # handle the case where this was deferred in case of multiple object storage relations
        # then azure relation severed
        if (
            not self.object_storage_config
            or not self.object_storage_config.azure
            or not self.object_storage_config.azure.credentials
        ):
            return

        payload = _make_os_secret_payload_azure(self.object_storage_config.azure)
        _publish_to_peers_with_secret(self.charm, "azure", payload)

        self.charm.keystore_manager.put_entries(
            {
                "azure.client.default.account": self.object_storage_config.azure.credentials.storage_account,
                "azure.client.default.key": self.object_storage_config.azure.credentials.secret_key,
            }
        )
        self.charm.keystore_manager.reload()
        self._ensure_repository(object_storage_type, self.object_storage_config)

    def _on_azure_credentials_gone(self, event: StorageConnectionInfoGoneEventAzure) -> None:
        """Handler for azure credentials gone event."""
        if self.object_storage_type == "conflict":
            return

        keystore_entries = ["azure.client.default.account", "azure.client.default.key"]
        if not self._cleanup(object_storage_type="azure", keystore_entries=keystore_entries):
            event.defer()
            return
        _clear_from_peers_and_delete_secret(self.charm)

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handler for s3 create backup action event."""
        if error_message := self._action_missing_pre_requisites():
            event.fail(error_message)
            return

        # Create a new snapshot
        try:
            snapshot_id = self.charm.snapshots_manager.create_snapshot(
                object_storage_type=self.object_storage_type
            )
        except OpenSearchHttpError as e:
            logger.error("Could not create a new snapshot: %s", e)
            event.fail(f"Backup request failed with: {str(e)}")
            return

        # Fetch the new snapshot for sanity check
        self.charm.status.set(MaintenanceStatus(BackupInProgress))
        try:
            snapshot = self.charm.snapshots_manager.get_snapshot(
                object_storage_type=self.object_storage_type, snapshot_id=snapshot_id
            )
            event.set_results({"backup-id": snapshot_id, "status": snapshot["state"]})
        except OpenSearchHttpError as e:
            logger.error("Unknown state for snapshot %s: %s", snapshot_id, e)
            event.fail(f"Unknown state for backup {snapshot_id}: {str(e)}")
        finally:
            self.charm.status.clear(BackupInProgress)

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Handler for list backups changes."""
        if error_message := self._action_missing_pre_requisites(report_running_operations=False):
            event.fail(error_message)
            return

        if (output_format := event.params.get("output", "").lower()) not in {"json", "table"}:
            event.fail("Failed: invalid output format, must be either 'json' or 'table'.")
            return

        try:
            snapshots = self.charm.snapshots_manager.list_snapshots(self.object_storage_type)
        except OpenSearchHttpError as e:
            logger.error("Could not fetch the list of snapshots: %s", e)
            event.fail(f"Backup request failed with: {str(e)}")
            return

        if output_format == "json":
            event.set_results({"backups": json.dumps(snapshots)})
            return

        # Format table output
        table_output = []

        header = "{:<20s} | {:s}".format("backup-id", "backup-status")
        table_output.append(header)
        table_output.append("-" * len(header))

        for _id, _snapshot in snapshots.items():
            line = "{:<20s} | {:s}".format(_id, _snapshot["state"])
            table_output.append(line)

        event.set_results({"backups": "\n".join(table_output)})

    def _on_restore_action(self, event: ActionEvent) -> None:  # noqa C901
        """Handler for the restore action."""
        snapshot_id = event.params.get("backup-id")
        if error_message := self._action_missing_pre_requisites():
            event.fail(error_message)
            return

        # Fetch the snapshot with the corresponding ID
        try:
            if not (
                snapshot := self.charm.snapshots_manager.get_snapshot(
                    self.object_storage_type, snapshot_id
                )
            ):
                logger.error("Backup %s not found", snapshot_id)
                event.fail(f"Backup {snapshot_id} not found.")
                return
        except OpenSearchHttpError as e:
            logger.error("Backup %s could not be fetched. Error: \n%s", snapshot_id, e)
            event.fail(f"Backup {snapshot_id} could not be fetched. Error: {str(e)}.")
            return

        # close indices that were snapshotted if they still exist, so they can be restored
        try:
            closed_indices, indices_failed_to_close = (
                self.charm.snapshots_manager.close_snapshot_indices_open_in_cluster(snapshot)
            )
            if indices_failed_to_close:
                event.fail(
                    f"Failed to close {len(indices_failed_to_close)} open indices. Check logs for details."
                )
                return
        except OpenSearchHttpError as e:
            event.fail(f"Failed to close open indices. Error: {str(e)}.")
            return

        # start the restore
        self.charm.status.set(MaintenanceStatus(RestoreInProgress))
        logger.info("Starting restore of snapshot %s.", snapshot_id)
        try:
            non_restored_indices = self.charm.snapshots_manager.restore_snapshot(
                object_storage_type=self.object_storage_type, snapshot=snapshot
            )
            if not non_restored_indices:
                self.charm.health.apply(wait_for_green_first=True, app=self.charm.unit.is_leader())
                return

            logger.error(
                "Failed to restore the following indices in snapshot %s: %s.",
                snapshot_id,
                non_restored_indices,
            )
            event.fail(
                f"Failed to restore {len(non_restored_indices)} indices. Check logs for details."
            )
        except OpenSearchHttpError as e:
            logger.error("Failed to restore snapshot %s. Error: %s.", snapshot_id, str(e))
            event.fail(f"Failed to restore snapshot {snapshot_id}. Error: {str(e)}.")
        finally:
            self.charm.status.clear(RestoreInProgress)

    def _on_peer_clusters_relation_changed_for_snapshots(self, event):  # noqa C901
        """Apply snapshots config when the orchestrator broadcasts over peer-clusters."""
        # Only leaders perform cluster-level config
        if not self.charm.unit.is_leader():
            return

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            event.defer()
            return

        # When it is the main orchestrator, it is same with single cluster
        # so we don't need to apply cluster-level config.
        if dep.typ == DeploymentType.MAIN_ORCHESTRATOR:
            return

        # read the effective storage type/config coming from peer-clusters
        os_type = self.charm.peers_data.get(Scope.APP, OS_PEER_KEY_TYPE)
        secret_id = self.charm.peers_data.get(Scope.APP, OS_PEER_KEY_SECRET)
        rev = self.charm.peers_data.get(Scope.APP, OS_PEER_KEY_REV)

        if not os_type or not secret_id or not rev:
            return

        # keep last seen revision in unit-scope, if changed, re-read secret
        last_rev = self.charm.peers_data.get(Scope.UNIT, OS_PEER_KEY_REV)
        if last_rev == rev:
            # nothing new
            return

        try:
            sec = self.charm.model.get_secret(id=secret_id)
            payload = sec.get_content()
        except Exception as e:
            logger.error("Failed to read object-storage secret %s: %s", secret_id, e)
            event.defer()
            return

        if payload.get("type") == "s3":
            self.charm.snapshots_manager.store_s3_ca(payload.get("tls_ca_chain") or None)
            self.charm.keystore_manager.put_entries(
                {
                    "s3.client.default.access_key": payload["access_key"],
                    "s3.client.default.secret_key": payload["secret_key"],
                }
            )
            effective_cfg = ObjectStorageConfig.from_dict(
                {
                    "s3": {
                        "endpoint": payload["endpoint"],
                        "bucket": payload["bucket"],
                        "base_path": payload["base_path"],
                        "region": payload["region"],
                        "credentials": {
                            "access-key": payload["access_key"],
                            "secret-key": payload["secret_key"],
                        },
                        "tls-ca-chain": payload.get("tls_ca_chain") or "",
                    }
                }
            )
        elif payload.get("type") == "azure":
            self.charm.keystore_manager.put_entries(
                {
                    "azure.client.default.account": payload["storage_account"],
                    "azure.client.default.key": payload["secret_key"],
                }
            )
            effective_cfg = ObjectStorageConfig.from_dict(
                {
                    "azure": {
                        "container": payload["container"],
                        "base_path": payload["base_path"],
                        "credentials": {
                            "storage-account": payload["storage_account"],
                            "secret-key": payload["secret_key"],
                        },
                    }
                }
            )
        else:
            # gcs branch
            return

        self.charm.keystore_manager.reload()

        need_restart = False
        try:
            need_restart = self.charm.snapshots_manager.should_restart_for_full_setup(
                object_storage_type=os_type + "-pcluster",
                object_storage_config=effective_cfg,
            )
        except OpenSearchHttpError as e:
            logger.warning("Skip restart precheck (OpenSearch not ready?): %s", e)
            need_restart = False

        if need_restart:
            if self.charm.request_opensearch_restart(reason="apply new object storage CA"):
                # record revision before leaving so we don't loop
                self.charm.peers_data.put(Scope.UNIT, OS_PEER_KEY_REV, rev)
                # defer only when we actually emitted the restart
                event.defer()
                return

        # ensure repository exists
        self._ensure_repository(os_type + "-pcluster", effective_cfg)

        # mark that we consumed this revision
        self.charm.peers_data.put(Scope.UNIT, OS_PEER_KEY_REV, rev)

    def _on_peer_clusters_relation_departed_for_snapshots(self, event):  # noqa C901
        """Cleanup snapshot config if the orchestrator we depended on is gone."""
        if not self.charm.unit.is_leader():
            return

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            return

        if dep.typ == DeploymentType.MAIN_ORCHESTRATOR:
            return

        rel_payload = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        typ_from_peer = None
        if rel_payload and getattr(rel_payload, "credentials", None):
            creds = rel_payload.credentials
            if getattr(creds, "s3", None):
                typ_from_peer = "s3-pcluster"
            elif getattr(creds, "azure", None):
                typ_from_peer = "azure-pcluster"
            elif getattr(creds, "gcs", None):
                typ_from_peer = "gcs-pcluster"

        if not typ_from_peer:
            typ_from_peer = self.charm.peers_data.get(Scope.UNIT, OS_PEER_KEY_TYPE)
            if not typ_from_peer:
                return

        if typ_from_peer == "s3-pcluster":
            keystore_entries = [
                "s3.client.default.access_key",
                "s3.client.default.secret_key",
            ]
        elif typ_from_peer == "azure-pcluster":
            keystore_entries = [
                "azure.client.default.account",
                "azure.client.default.key",
            ]
        else:  # gcs-pcluster: currently no keystore entries
            keystore_entries = []

        if not self._cleanup(
            object_storage_type=typ_from_peer,
            keystore_entries=keystore_entries,
        ):
            event.defer()
            return

        if (
            typ_from_peer == "s3-pcluster"
            and self.charm.snapshots_manager.is_custom_s3_ca_stored()
        ):
            self.charm.snapshots_manager.store_s3_ca(s3_tls_ca_chain=None)
            if self.charm.request_opensearch_restart(reason="clean up the object storage CA"):
                return

        try:
            self.charm.peers_data.delete(Scope.UNIT, OS_PEER_KEY_TYPE)
        except Exception:
            pass
        try:
            self.charm.peers_data.delete(Scope.UNIT, OS_PEER_KEY_REV)
        except Exception:
            pass

        logger.info(
            "Peer-cluster departed: cleared snapshot configuration for storage type %s",
            typ_from_peer,
        )

    def _cleanup(
        self, object_storage_type: ObjectStorageType | None, keystore_entries: list[str]
    ) -> bool:
        """Cleanup the object storage stored configuration."""
        if not object_storage_type:
            return True

        try:
            self.charm.snapshots_manager.remove_repo(object_storage_type=object_storage_type)
            self.charm.keystore_manager.remove_entries(keystore_entries)
            self.charm.keystore_manager.reload()
            self.charm.peers_data.delete(Scope.UNIT, OS_PEER_KEY_TYPE)
            return True
        except OpenSearchHttpError as e:
            logger.error("Cleanup of the %s cluster config failed: %s", object_storage_type, e)
            return False

    @property
    def object_storage_type(self) -> ObjectStorageType | None:  # noqa C901
        """Get the current object storage type."""
        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep or dep.typ in {DeploymentType.MAIN_ORCHESTRATOR}:
            active_rels = [
                rel
                for rel in [
                    self.charm.model.get_relation(S3_RELATION),
                    self.charm.model.get_relation(AZURE_RELATION),
                    self.charm.model.get_relation(GCS_RELATION),
                ]
                if rel
            ]
            if len(active_rels) > 1:
                return "conflict"
            if self.charm.model.get_relation(S3_RELATION):
                return "s3"
            if self.charm.model.get_relation(AZURE_RELATION):
                return "azure"
            if self.charm.model.get_relation(GCS_RELATION):
                return "gcs"
            if typ := self.charm.peers_data.get(Scope.UNIT, OS_PEER_KEY_TYPE):
                return typ
            return None

        pcluster_rel_data = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        if not pcluster_rel_data or not pcluster_rel_data.credentials:
            return None

        if pcluster_rel_data.credentials.s3:
            return "s3-pcluster"
        if pcluster_rel_data.credentials.azure:
            return "azure-pcluster"
        if pcluster_rel_data.credentials.gcs:
            return "gcs-pcluster"

        if typ := self.charm.peers_data.get(Scope.UNIT, OS_PEER_KEY_TYPE):
            return typ

        return None

    @property
    def object_storage_config(self) -> ObjectStorageConfig | None:
        """Fetch the object storage data depending on the relation."""
        if not (object_storage_type := self.object_storage_type):
            return None

        if object_storage_type == "conflict":
            return None

        if object_storage_type == "s3":
            return ObjectStorageConfig(
                s3=S3RelData.from_relation(self.s3_requirer.get_s3_connection_info())
            )

        if object_storage_type == "azure":
            return ObjectStorageConfig(
                azure=AzureRelData.from_relation(
                    self.azure_requirer.get_azure_storage_connection_info()
                )
            )

        if object_storage_type == "gcs":
            gcs_rel = self.charm.model.get_relation(GCS_RELATION)
            if not gcs_rel or not gcs_rel.app:
                return None

        pcluster_rel_data = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        if object_storage_type == "s3-pcluster":
            data = S3RelData.from_dict(
                {
                    "credentials": pcluster_rel_data.credentials.s3,
                    "tls-ca-chain": pcluster_rel_data.s3_tls_ca_chain,
                }
            )
            return ObjectStorageConfig(s3=data)

        if object_storage_type == "azure-pcluster":
            data = AzureRelData.from_dict({"credentials": pcluster_rel_data.credentials.azure})
            return ObjectStorageConfig(azure=data)

        data = GcsRelData.from_dict({"credentials": pcluster_rel_data.credentials.gcs})
        return ObjectStorageConfig(gcs=data)

    def _action_missing_pre_requisites(  # noqa C901
        self, report_running_operations: bool = True
    ) -> str | None:
        """Compute the missing prerequisites for running a snapshot/restore action."""
        if not self.charm.unit.is_leader():
            return "Backup/Restore related actions must be run on the juju leader unit."

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            return "Deployment not ready."

        if self.charm.upgrade_in_progress:
            return "Backup/Restore operations not supported while upgrade in-progress."

        ost = self.object_storage_type
        if not ost:
            return "Missing relation with an object storage integrator."

        if ost == "conflict":
            return "Conflict: more than one object storage integrators integrated."

        if not self.charm.opensearch.is_node_up() and not self.charm.alt_hosts:
            return "Connectivity issue: the opensearch service is not reachable."

        repo_name = self.charm.snapshots_manager.repository_name(ost)
        logger.debug(
            f"[snapshots] precheck: type={ost} repo={repo_name} alt_hosts={self.charm.alt_hosts}"
        )

        try:
            if not self.charm.snapshots_manager.is_repository_created(ost):
                osc = self.object_storage_config
                if not osc:
                    return "Object storage configuration not ready."
                logger.info(f"[snapshots] repo {repo_name} missing; attempting create.")
                self.charm.snapshots_manager.create_repo(ost, osc)
                if not self.charm.snapshots_manager.is_repository_created(ost):
                    return "The opensearch repository has not been created yet."
        except OpenSearchHttpError as e:
            return f"Action failed with: {str(e)}."

        if not report_running_operations:
            return None

        match self.charm.health.get(wait_for_green_first=True):
            case HealthColors.RED:
                return "Cluster health red, current state must be resolved before."
            case HealthColors.YELLOW_TEMP:
                return "Shards are still relocating or initializing."
            case HealthColors.UNKNOWN:
                return "Cluster health unknown."

        try:
            if (
                self.charm.snapshots_manager.is_snapshot_running()
                or self.charm.snapshots_manager.is_restore_running()
            ):
                return "Backup / Restore operation in progress."
        except OpenSearchHttpError as e:
            return f"Action failed with: {str(e)}."

        return None

    def _ensure_repository(self, obj_type, obj_cfg) -> None:
        """Create the repository if we have a storage type/config and it doesn't exist yet."""
        if not obj_type or not obj_cfg or obj_type == "conflict":
            return
        try:
            if not self.charm.snapshots_manager.is_repository_created(obj_type):
                self.charm.snapshots_manager.create_repo(
                    object_storage_type=obj_type,
                    object_storage_config=obj_cfg,
                )
                logger.info("Created snapshot repository for %s", obj_type)
        except OpenSearchHttpError as e:
            logger.error("ensure_repository failed: %s", e)


class OpenSearchSnapshotsManager:
    """Manager class for Backups (snapshots)."""

    def __init__(self, charm: "OpenSearchBaseCharm", opensearch: "OpenSearchDistribution"):
        self.charm = charm  # todo this will need to be replaced by the clusterState
        self.opensearch = opensearch

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def create_repo(
        self,
        object_storage_type: ObjectStorageType,
        object_storage_config: ObjectStorageConfig,
        name: str | None = None,
    ) -> str:
        """Create an opensearch 'repository' for storing backups."""
        repo_name = name or self.repository_name(object_storage_type)
        settings = {}
        if object_storage_type in {"s3", "s3-pcluster"}:
            settings = {
                "bucket": object_storage_config.s3.bucket,
                "base_path": object_storage_config.s3.base_path,
                "region": object_storage_config.s3.region,
                "endpoint": object_storage_config.s3.endpoint,
            }

        elif object_storage_type in {"azure", "azure-pcluster"}:
            settings = {
                "container": object_storage_config.azure.container,
                "base_path": object_storage_config.azure.base_path,
            }
        elif object_storage_type in {"gcs", "gcs-pcluster"}:
            settings = {
                "bucket": object_storage_config.gcs.bucket,
                "base_path": object_storage_config.gcs.base_path,
            }
        repo_type = self._repo_type(object_storage_type)
        response = self.opensearch.request(
            "PUT",
            f"_snapshot/{repo_name}?verify=false",
            payload={"type": repo_type, "settings": settings},
        )
        logger.debug("Snapshot repository creation response: %s", response)

        # This should always pass and is set for documentation purposes
        assert response.get("acknowledged") is True
        return repo_name

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def remove_repo(self, object_storage_type: ObjectStorageType) -> None:
        """Remove the current repository."""
        repo_name = self.repository_name(object_storage_type)
        try:
            response = self.opensearch.request(
                "DELETE", f"_snapshot/{repo_name}", alt_hosts=self.charm.alt_hosts
            )
            logger.debug("Snapshot repository creation response: %s", response)

            # This should always pass and is set for documentation purposes
            assert response.get("acknowledged") is True
        except OpenSearchHttpError as e:
            # we might be attempting to delete a nonexisting repository
            if e.response_body.get("error", {}).get("type") == "repository_missing_exception":
                return
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def create_snapshot(self, object_storage_type: ObjectStorageType) -> str:
        """Create an OpenSearch snapshot."""
        repo_name = self.repository_name(object_storage_type)
        snapshot_id = datetime.now().strftime(OPENSEARCH_BACKUP_ID_FORMAT).lower()
        ignore = [f"-{idx}" for idx in SYSTEM_INDICES]
        indices_clause = ",".join(["*"] + ignore)

        # create snapshot
        response = self.opensearch.request(
            "PUT",
            f"_snapshot/{repo_name}/{snapshot_id}?wait_for_completion=false",
            payload={"indices": indices_clause},
            alt_hosts=self.charm.alt_hosts,
            timeout=30,
        )

        logger.info(f"Snapshot request submitted with backup-id: {snapshot_id}")
        logger.debug(f"Create snapshot request with id: {snapshot_id} - response: {response}")

        # This should always pass and is set for documentation purposes
        assert response.get("accepted") is True

        return snapshot_id

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(3),
        retry=retry_if_exception_type(OpenSearchHttpError),
        reraise=True,
    )
    def restore_snapshot(
        self, object_storage_type: ObjectStorageType, snapshot: dict[str, Any]
    ) -> set[str]:
        """Restore an OpenSearch snapshot."""
        repo_name = self.repository_name(object_storage_type)
        snapshot_id = snapshot.get("snapshot")

        # This is not necessary if our charm performed the backup itself, but we add this
        # as a safeguard against manually run backups (through direct calls to the rest api)
        indices_to_ignore = "-,".join(
            SYSTEM_INDICES
        )  # the prefix dash ensures opensearch discards it

        restore_id = f"restore:{datetime.now().strftime(OPENSEARCH_BACKUP_ID_FORMAT).lower()}-snapshot:{snapshot_id}"

        # restore
        restore_resp = self.opensearch.request(
            "POST",
            f"_snapshot/{repo_name}/{snapshot_id}/_restore?wait_for_completion=true",
            headers={"X-Opaque-Id": restore_id},
            payload={"indices": f"*,-{indices_to_ignore}"},
            alt_hosts=self.charm.alt_hosts,
        )
        logger.info("Restore of snapshot '%s' response: %s", snapshot_id, restore_resp)

        # this only serves as documentation and should always be true if no previous HTTP error
        assert restore_resp["snapshot"] == snapshot_id

        # sanity check on the restore success
        recovery_resp: list[dict[str, str]] = self.opensearch.request(
            "GET", "_cat/recovery?format=json"
        )
        snapshot_recoveries = [
            recovery
            for recovery in recovery_resp
            if (
                recovery["type"] == "snapshot"
                and recovery["repository"] == repo_name
                and recovery["snapshot"] == snapshot_id
            )
        ]
        restored_indices = set(
            [recovery["index"] for recovery in snapshot_recoveries if recovery["stage"] == "done"]
        )
        expected_indices = set(snapshot.get("indices", []))
        return expected_indices - restored_indices

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def close_snapshot_indices_open_in_cluster(
        self, snapshot: dict[str, Any]
    ) -> Tuple[list[str] | None, dict[str, Any] | None]:
        """Close the non-system indices included in a given snapshot."""
        if not (indices_to_close := self._get_snapshot_indices_open_in_cluster(snapshot)):
            logger.info("No indices to close.")
            return None, None

        logger.info("Attempting closing the indices: %s", indices_to_close)
        response = self.opensearch.request("POST", f"{','.join(indices_to_close)}/_close")

        # verify that the relevant indices are closed
        if response["acknowledged"] and response["shards_acknowledged"]:
            logger.info("Successfully closed all indices: %s.", indices_to_close)
            return indices_to_close, None

        indices_failed_to_close = {
            index: payload
            for index, payload in response["indices"].items()
            if not payload["closed"]
        }
        closed_indices = [
            index for index in indices_to_close if index not in indices_failed_to_close
        ]

        logger.error("Failed to close some indices: \n%s", indices_failed_to_close)
        return closed_indices, indices_failed_to_close

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def _get_snapshot_indices_open_in_cluster(self, snapshot: dict[str, Any]) -> list[str]:
        """Fetch the current open indices in the current cluster."""
        current_indices = ClusterState.indices(self.opensearch)
        return sorted(
            [
                index
                for index in snapshot.get("indices", [])
                if index in current_indices
                and index not in SYSTEM_INDICES
                and current_indices[index]["state"] == "open"
            ]
        )

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def get_snapshot(
        self, object_storage_type: ObjectStorageType, snapshot_id: str
    ) -> dict[str, Any] | None:
        """Fetch a snapshot by id."""
        repo_name = self.repository_name(object_storage_type)
        try:
            response = self.opensearch.request(
                "GET", f"_snapshot/{repo_name}/{snapshot_id}", alt_hosts=self.charm.alt_hosts
            )
            return response["snapshots"][0]
        except OpenSearchHttpError as e:
            if e.response_body.get("error", {}).get("type") == "snapshot_missing_exception":
                return None
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def list_snapshots(self, object_storage_type: ObjectStorageType) -> dict[Any, dict[str, Any]]:
        """List all snapshots in the current repository."""
        repo_name = self.repository_name(object_storage_type)
        response = self.opensearch.request(
            "GET", f"_snapshot/{repo_name}/_all", alt_hosts=self.charm.alt_hosts
        )
        snapshots = {
            snapshot["snapshot"].upper(): {
                "state": snapshot["state"].lower(),
                "indices": snapshot.get("indices", []),
            }
            for snapshot in response.get("snapshots", [])
        }
        return dict(sorted(snapshots.items(), reverse=True))

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def is_repository_created(
        self, object_storage_type: ObjectStorageType, repository: str = None
    ) -> bool:
        """Check if a repository is created."""
        repo_name = repository or self.repository_name(object_storage_type)
        try:
            response = self.opensearch.request(
                "GET", f"_snapshot/{repo_name}", alt_hosts=self.charm.alt_hosts
            )
            return response.get(repo_name) is not None
        except OpenSearchHttpError as e:
            if e.response_body.get("error", {}).get("type") == "repository_missing_exception":
                return False
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def is_snapshot_running(self) -> bool:
        """Check if a snapshot is running."""
        response = self.opensearch.request(
            "GET", "_snapshot/_status", alt_hosts=self.charm.alt_hosts
        )
        return len(response.get("snapshots", [])) > 0

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def is_restore_running(self) -> bool:
        """Check if a restore operation is running."""
        response: list[dict[str, str]] = self.opensearch.request(
            "GET", "/_cat/recovery?format=json&h=type,stage", alt_hosts=self.charm.alt_hosts
        )
        for operation in response:
            if operation["type"] == "snapshot" and operation["stage"] == "open":
                return True
        return False

    def repository_name(self, object_storage_type: ObjectStorageType) -> str | None:
        """Get the repository name for a given storage type."""
        if object_storage_type in {"s3", "s3-pcluster"}:
            return "s3-repository"

        if object_storage_type in {"azure", "azure-pcluster"}:
            return "azure-repository"

        return "gcs-repository"

    def requires_custom_s3_ca(
        self, object_storage_type: ObjectStorageType, object_storage_config: ObjectStorageConfig
    ) -> bool:
        """Check if the current object storage setup requires the use of a custom CA."""
        if object_storage_type not in {"s3", "s3-pcluster"}:
            return False

        cas = (
            list_cas(store_pwd="changeit", store_path=f"{self.opensearch.paths.certs}/cacerts.p12")
            or {}
        )
        chain = (object_storage_config.s3 and object_storage_config.s3.tls_ca_chain) or None
        if not chain:
            return False

        return "s3-snapshots-gateway-0" not in cas

    def is_custom_s3_ca_stored(self, s3_ca_chain: str | None = None) -> bool:
        """Check if a custom CA for the object storage is stored in the cacerts trust store."""
        stored_cacerts = (
            list_cas(store_pwd="changeit", store_path=f"{self.opensearch.paths.certs}/cacerts.p12")
            or {}
        )
        if not s3_ca_chain:
            return stored_cacerts.get("s3-snapshots-gateway") is not None

        def _normalize_pem(s: str) -> str:
            return "\n".join([line.rstrip() for line in s.strip().splitlines()])

        val = stored_cacerts.get("s3-snapshots-gateway")
        return _normalize_pem(val) == _normalize_pem(s3_ca_chain) if val else False

    def store_s3_ca(self, s3_tls_ca_chain: str | None) -> None:
        """Store or remove an s3 TLS CA chain on the cacerts trust store."""
        if s3_tls_ca_chain:
            store_ca(
                store_pwd="changeit",
                store_path=f"{self.opensearch.paths.certs}/cacerts.p12",
                alias="s3-snapshots-gateway",
                ca=s3_tls_ca_chain,
                keep_previous=False,
            )
        else:
            remove_ca(
                alias="s3-snapshots-gateway",
                store_pwd="changeit",
                store_path=f"{self.opensearch.paths.certs}/cacerts.p12",
            )

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def should_restart_for_full_setup(
        self, object_storage_type: ObjectStorageType, object_storage_config: ObjectStorageConfig
    ) -> bool:
        """Check if a restart is needed for full setup."""
        if not self.opensearch.is_started():
            raise OpenSearchHttpError("node unavailable")

        try:
            test_repo = f"tmp-{self.charm.unit_name}-{self.repository_name(object_storage_type)}"
            self.create_repo(object_storage_type, object_storage_config, name=test_repo)
            # best effort clean up
            try:
                self.remove_repo(object_storage_type)
            except Exception:
                pass
            # creation succeeded, no restart needed
            return False
        except OpenSearchHttpError as e:
            if e.response_body.get("error", {}).get("type") == "repository_verification_exception":
                return True
            raise

    def _repo_type(self, object_storage_type: ObjectStorageType) -> str:
        if object_storage_type in {"s3", "s3-pcluster"}:
            return "s3"
        if object_storage_type in {"azure", "azure-pcluster"}:
            return "azure"
        if object_storage_type in {"gcs", "gcs-pcluster"}:
            return "gcs"


# helpers
def _make_os_secret_payload_s3(rel_data: S3RelData) -> dict:
    return {
        "type": "s3",
        "endpoint": rel_data.endpoint,
        "bucket": rel_data.bucket,
        "base_path": rel_data.base_path,
        "region": rel_data.region,
        "access_key": rel_data.credentials.access_key,
        "secret_key": rel_data.credentials.secret_key,
        "tls_ca_chain": rel_data.tls_ca_chain or "",
    }


def _make_os_secret_payload_azure(rel_data: AzureRelData) -> dict:
    return {
        "type": "azure",
        "container": rel_data.container,
        "base_path": rel_data.base_path,
        "storage_account": rel_data.credentials.storage_account,
        "secret_key": rel_data.credentials.secret_key,
    }


def _bump_revision(cur: Optional[str]) -> int:
    try:
        return int(cur) + 1
    except Exception:
        return 1


def _publish_to_peers_with_secret(charm, os_type: str, payload: dict) -> None:
    """Create a new secret with payload, grant it to peer-cluster, and publish keys + revision."""
    # best-effort delete old secret first
    old_secret_id = charm.peers_data.get(Scope.APP, OS_PEER_KEY_SECRET)
    if old_secret_id:
        try:
            old_sec = charm.model.get_secret(id=old_secret_id)
            # remove the whole secret so consumers can't fetch old revision
            old_sec.remove_all_revisions()
        except Exception:
            pass

    # create a new secret
    sec: Secret = charm.app.add_secret(payload)
    secret_id = sec.id

    # grant to peer-cluster relation
    rel: Relation | None = charm.model.get_relation(PeerClusterRelationName)
    if rel:
        try:
            sec.grant(relation=rel)
        except Exception:
            pass

    # bump and publish revision
    cur_rev = charm.peers_data.get(Scope.APP, OS_PEER_KEY_REV)
    new_rev = _bump_revision(cur_rev)

    charm.peers_data.put_object(Scope.APP, {OS_PEER_KEY_TYPE: os_type})
    charm.peers_data.put_object(Scope.APP, {OS_PEER_KEY_SECRET: secret_id})
    charm.peers_data.put_object(Scope.APP, {OS_PEER_KEY_REV: str(new_rev)})


def _clear_from_peers_and_delete_secret(charm) -> None:
    old_secret_id = charm.peers_data.get(Scope.APP, OS_PEER_KEY_SECRET)
    if old_secret_id:
        try:
            sec = charm.model.get_secret(id=old_secret_id)
            sec.remove_all_revisions()
        except Exception:
            pass
    new_rev = 0
    # clear type and secret, set revision to 0 so non-orchestrators drop local state
    charm.peers_cm.delete(Scope.APP, OS_PEER_KEY_TYPE)
    charm.peers_cm.delete(Scope.APP, OS_PEER_KEY_SECRET)
    charm.peers_cm.put_object(OS_PEER_KEY_REV, str(new_rev))
