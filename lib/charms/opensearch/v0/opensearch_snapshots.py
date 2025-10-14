# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Snapshots."""

import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Tuple

from charms.data_platform_libs.v0.data_interfaces import Scope
from charms.data_platform_libs.v0.object_storage import (
    AzureStorageRequires,
    StorageConnectionInfoChangedEvent,
    StorageConnectionInfoGoneEvent,
)
from charms.data_platform_libs.v0.s3 import (
    CredentialsChangedEvent,
    CredentialsGoneEvent,
    S3Requirer,
)
from charms.opensearch.v0.constants_charm import (
    AZURE_RELATION,
    GCS_RELATION,
    OPENSEARCH_BACKUP_ID_FORMAT,
    S3_RELATION,
    BackupInProgress,
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
from charms.opensearch.v0.constants_charm import PeerClusterRelationName
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_locking import OpenSearchNodeLock
from ops import (
    ActionEvent,
    BlockedStatus,
    MaintenanceStatus,
    Object,
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
        self.s3_requirer = S3Requirer(charm, S3_RELATION)
        self.azure_requirer = AzureStorageRequires(charm, AZURE_RELATION)
        self.gcs_requirer = AzureStorageRequires(charm, GCS_RELATION)

        # simple deployments or to main orchestrator
        self.framework.observe(
            self.s3_requirer.on.credentials_changed, self._on_s3_credentials_changed
        )
        self.framework.observe(self.s3_requirer.on.credentials_gone, self._on_s3_credentials_gone)
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

    def _on_s3_credentials_changed(self, event: CredentialsChangedEvent) -> None:
        """Handler for s3 credentials changed event."""
        object_storage_type = self.object_storage_type or "s3"
        self.charm.peers_data.put(Scope.UNIT, "snapshot-object-storage-type", object_storage_type)

        if object_storage_type == "conflict":
            self.charm.status.set(BlockedStatus("More than 1 object storage relation..."))
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

        self.charm.snapshots_manager.store_s3_ca(self.object_storage_config.s3.tls_ca_chain)

        s3_credentials = self.object_storage_config.s3.credentials
        self.charm.keystore_manager.put_entries(
            {
                "s3.client.default.access_key": s3_credentials.access_key,
                "s3.client.default.secret_key": s3_credentials.secret_key,
            }
        )
        self.charm.keystore_manager.reload()

        if self.charm.snapshots_manager.should_restart_for_full_setup(
            object_storage_type=object_storage_type,
            object_storage_config=self.object_storage_config,
        ):
            if self.charm.request_opensearch_restart(reason="apply new object storage CA"):
                event.defer()
                return

        self._ensure_repository()

    def _on_s3_credentials_gone(self, event: CredentialsGoneEvent) -> None:
        """Handler for s3 credentials gone event."""
        if not (object_storage_type := self.object_storage_type):
            return

        if object_storage_type == "conflict":
            return

        keystore_entries = ["s3.client.default.access_key", "s3.client.default.secret_key"]
        if not self._cleanup(
            object_storage_type=object_storage_type, keystore_entries=keystore_entries
        ):
            event.defer()
            return

        self.charm.peers_data.delete(Scope.UNIT, "snapshot-object-storage-type")

        if not self.charm.snapshots_manager.is_custom_s3_ca_stored():
            return

        # remove the CA from the cacerts trust store
        self.charm.snapshots_manager.store_s3_ca(s3_tls_ca_chain=None)

        # restart opensearch to clean up the new CA if the service is up
        if self.charm.request_opensearch_restart(reason="clean up the object storage CA"):
            return

    def _on_azure_credentials_changed(self, event: StorageConnectionInfoChangedEvent) -> None:
        """Handler for azure credentials changed event."""
        object_storage_type = self.object_storage_type or "azure"
        self.charm.peers_data.put(Scope.UNIT, "snapshot-object-storage-type", object_storage_type)

        if object_storage_type == "conflict":
            self.charm.status.set(BlockedStatus("More than 1 object storage relation..."))
            event.defer()
            return

        # handle the case where this was deferred in case of multiple object storage relations
        # then azure relation severed
        if object_storage_type != "azure":
            return

        azure_credentials = self.object_storage_config.azure.credentials
        self.charm.keystore_manager.put_entries(
            {
                "azure.client.default.account": azure_credentials.storage_account,
                "azure.client.default.key": azure_credentials.secret_key,
            }
        )
        self.charm.keystore_manager.reload()

        self._ensure_repository()

    def _on_azure_credentials_gone(self, event: StorageConnectionInfoGoneEvent) -> None:
        """Handler for azure credentials gone event."""
        if not (object_storage_type := self.object_storage_type):
            return

        if object_storage_type == "conflict":
            return

        keystore_entries = ["azure.client.default.account", "azure.client.default.key"]
        if not self._cleanup(
            object_storage_type=object_storage_type, keystore_entries=keystore_entries
        ):
            event.defer()
            return
        self.charm.peers_data.delete(Scope.UNIT, "snapshot-object-storage-type")

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handler for s3 create backup action event."""
        if error_message := self._action_missing_pre_requisites():
            event.fail(error_message)
            return

        # Create new snapshot
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
        """Handler for list backups  changes."""
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
            if not (snapshot := self.charm.snapshots_manager.get_snapshot(self.object_storage_type, snapshot_id)):
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

    def _on_peer_clusters_relation_changed_for_snapshots(self, event):
        """Apply snapshots config when the orchestrator broadcasts credentials over peer-clusters."""
        # Only leaders perform cluster-level config
        if not self.charm.unit.is_leader():
            return

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            event.defer()
            return

        # In large deployments we only react here when NOT the main orchestrator
        if dep.typ == DeploymentType.MAIN_ORCHESTRATOR:
            return

        # Read the effective storage type/config coming from peer-clusters
        object_storage_type = self.object_storage_type
        object_storage_config = self.object_storage_config

        # Nothing to do if not ready
        if not object_storage_type or not object_storage_config:
            return

        if object_storage_type == "conflict":
            self.charm.status.set(BlockedStatus("More than 1 object storage relation..."))
            event.defer()
            return
        #  store/remove custom S3 CA only for S3
        if object_storage_type == "s3-pcluster":
            self.charm.snapshots_manager.store_s3_ca(object_storage_config.s3.tls_ca_chain)
            credentials = object_storage_config.s3.credentials
            self.charm.keystore_manager.put_entries(
                {
                    "s3.client.default.access_key": credentials.access_key,
                    "s3.client.default.secret_key": credentials.secret_key,
                }
            )
        elif object_storage_type == "azure-pcluster":
            credentials = object_storage_config.azure.credentials
            self.charm.keystore_manager.put_entries(
                {
                    "azure.client.default.account": credentials.storage_account,
                    "azure.client.default.key": credentials.secret_key,
                }
            )
        else:
            # gcs-pcluster currently has no keystore credentials to set yet
            credentials = None

        self.charm.keystore_manager.reload()

        if self.charm.snapshots_manager.should_restart_for_full_setup(
            object_storage_type=object_storage_type,
            object_storage_config=object_storage_config,
        ):
            if self.charm.request_opensearch_restart(reason="apply new object storage CA"):
                event.defer()
                return

        # ensure repository exists
        self._ensure_repository()

    def _on_peer_clusters_relation_departed_for_snapshots(self, event):
        """Cleanup snapshot config if the orchestrator we depended on is gone."""
        if not self.charm.unit.is_leader():
            return

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            return

        # If we were configured via peer-clusters and the orchestrator relation is leaving,
        # remove the repo and any custom CA we set for S3.
        object_storage_type = self.object_storage_type

        # Nothing to do if not ready
        if not object_storage_type:
            return

        if object_storage_type == "conflict":
            return

        if object_storage_type == "s3-pcluster":
            keystore_entries = ["s3.client.default.access_key", "s3.client.default.secret_key"]
        elif object_storage_type == "azure-pcluster":
            keystore_entries = ["azure.client.default.account", "azure.client.default.key"]
        else:
            keystore_entries = [] # gcs credentials

        if not self._cleanup(
            object_storage_type=object_storage_type, keystore_entries=keystore_entries
        ):
            event.defer()
            return

        if object_storage_type in {"s3-pcluster"} and self.charm.snapshots_manager.is_custom_s3_ca_stored():
            self.charm.snapshots_manager.store_s3_ca(s3_tls_ca_chain=None)
            # restart opensearch to clean up the new CA if the service is up
            if self.charm.request_opensearch_restart(reason="clean up the object storage CA"):
                return


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
            self.charm.peers_data.delete(Scope.UNIT, "snapshot-object-storage-type")
            return True
        except OpenSearchHttpError as e:
            logger.error("Cleanup of the %s cluster config failed: %s", object_storage_type, e)
            return False

    @property
    def object_storage_type(self) -> ObjectStorageType | None:  # noqa C901
        """Get the current object storage type."""
        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep or dep.typ in {DeploymentType.MAIN_ORCHESTRATOR, DeploymentType.OTHER}:
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
            if typ := self.charm.peers_data.get(Scope.UNIT, "snapshot-object-storage-type"):
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

        if typ := self.charm.peers_data.get(Scope.UNIT, "snapshot-object-storage-type"):
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
            # TODO: get gcs data from relation data properly

        pcluster_rel_data = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        if object_storage_type == "s3-pcluster":
            data = S3RelData.from_dict(
                {
                    "credentials": pcluster_rel_data.credentials.s3,
                    "tls-ca-chain": pcluster_rel_data.credentials.s3_tls_ca_chain,
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

        if not self.object_storage_type:
            return "Missing relation with an object storage integrator."

        if self.object_storage_type == "conflict":
            return "Conflict: more than one object storage integrators integrated."

        if not self.charm.opensearch.is_node_up() and not self.charm.alt_hosts:
            return "Connectivity issue: the opensearch service is not reachable."

        try:
            if not self.charm.snapshots_manager.is_repository_created(self.object_storage_type):
                self._ensure_repository()
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

    def _ensure_repository(self) -> None:
        """Create the repository if we have a storage type/config and it doesn't exist yet."""
        obj_type = self.object_storage_type
        obj_cfg = self.object_storage_config
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
            settings = object_storage_config.s3.model_dump(
                exclude={"tls_ca_chain", "credentials"}, exclude_none=True
            )
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
        repo_type = self._backend_type(object_storage_type)
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

        indices_to_ignore = "-,".join(
            SYSTEM_INDICES
        )  # the prefix dash ensures opensearch discards it
        response = self.opensearch.request(
            "PUT",
            f"_snapshot/{repo_name}/{snapshot_id}?wait_for_completion=false",
            payload={"indices": f"*, -{indices_to_ignore}"},
            alt_hosts=self.charm.alt_hosts,
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

        stored_cacerts = list_cas(
            store_pwd="changeit", store_path=f"{self.opensearch.paths.certs}/cacerts.p12"
        ).values()
        if (
            object_storage_config.s3
            and object_storage_config.s3.tls_ca_chain
            and object_storage_config.s3.tls_ca_chain not in stored_cacerts
        ):
            return True

        return False

    def is_custom_s3_ca_stored(self, s3_ca_chain: str | None = None) -> bool:
        """Check if a custom CA for the object storage is stored in the cacerts trust store."""
        stored_cacerts = list_cas(
            store_pwd="changeit", store_path=f"{self.opensearch.paths.certs}/cacerts.p12"
        )
        if not s3_ca_chain:
            return stored_cacerts.get("s3-snapshots-gateway") is not None

        return stored_cacerts.get("s3-snapshots-gateway") == s3_ca_chain

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
        self,
        object_storage_type: ObjectStorageType,
        object_storage_config: ObjectStorageConfig
    ) -> bool:
        """Check if a restart is needed for full setup."""
        if not self.opensearch.is_started():
            return False

        try:
            test_repo =  f"tmp-{self.charm.unit_name}-{self.repository_name(object_storage_type)}"
            self.create_repo(object_storage_type, object_storage_config, name=test_repo)
            # best effort clean up
            try:
                self.remove_repo(object_storage_type)
            except Exception:
                pass
            # creation succeded, no restart needed
            return False
        except OpenSearchHttpError as e:
            if e.response_body.get("error", {}).get("type") == "repository_verification_exception":
                return True
            raise

    def _backend_type(self, object_storage_type: ObjectStorageType) -> str:
        if object_storage_type in {"s3", "s3-pcluster"}:
            return "s3"
        if object_storage_type in {"azure", "azure-pcluster"}:
            return "azure"
        if object_storage_type in {"gcs", "gcs-pcluster"}:
            return "gcs"
