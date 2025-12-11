# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Snapshots."""
import hashlib
import json
import logging
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional, Tuple, Union

from charms.data_platform_libs.v0.azure_storage import (
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
    BackupCredentialCleanupFailed,
    BackupCredentialIncorrect,
    BackupInProgress,
    BackupMisconfiguration,
    BackupRelConflict,
    BackupRelDataIncomplete,
    BackupRelShouldNotExist,
    PClusterMissingStorageRelations,
    PeerClusterOrchestratorRelationName,
    PeerClusterRelationName,
    RestoreInProgress,
)
from charms.opensearch.v0.helper_charm import Status
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.helper_security import (
    list_cas,
    normalize_certificate_chain_unordered,
    remove_s3_ca,
    store_s3_ca,
    verify_azure_credentials,
    verify_s3_credentials,
)
from charms.opensearch.v0.models import (
    AzureRelData,
    DeploymentType,
    ObjectStorageConfig,
    PeerClusterRelData,
    S3RelData,
)
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_locking import OpenSearchNodeLock
from ops import (
    ActionEvent,
    BlockedStatus,
    EventBase,
    EventSource,
    MaintenanceStatus,
    Object,
)
from pydantic import ValidationError
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


# OpenSearch Backups
S3_REPOSITORY = "s3-repository"
AZURE_REPOSITORY = "azure-repository"
GCS_REPOSITORY = "gcs-repository"
S3_CA_ALIAS = "s3-snapshots-gateway"
STORE_PASSWORD = "changeit"
# System indices that should not be snapshotted/restored
SYSTEM_INDICES = {
    ".opendistro_security",
    ".opensearch-sap-log-types-config",
    OpenSearchNodeLock.OPENSEARCH_INDEX,
}


class ObjectStorageType(str, Enum):
    """The object storage types."""

    S3 = "s3"
    AZURE = "azure"
    GCS = "gcs"
    S3_PCLUSTER = "s3-pcluster"
    AZURE_PCLUSTER = "azure-pcluster"
    GCS_PCLUSTER = "gcs-pcluster"
    CONFLICT = "conflict"


class VerifyBackupCredentialsEvent(EventBase):
    """Event to verify backup credentials on main orchestrator leader unit."""


class OpenSearchSnapshotEvents(Object):
    """Events class for Backups (snapshots)."""

    verify_backup_credentials_event = EventSource(VerifyBackupCredentialsEvent)

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ):
        super().__init__(charm, key="backups")
        self.charm = charm

        # requirers
        self.s3_requirer = S3Requirer(charm, S3_RELATION)
        self.azure_requirer = AzureStorageRequires(charm, AZURE_RELATION)

        # simple deployments or main orchestrator
        for event in [
            self.s3_requirer.on.credentials_changed,
            self.azure_requirer.on.storage_connection_info_changed,
        ]:
            self.framework.observe(event, self._on_backup_credentials_changed)

        for event in [
            self.s3_requirer.on.credentials_gone,
            self.azure_requirer.on.storage_connection_info_gone,
        ]:
            self.framework.observe(event, self._on_backup_credentials_gone)

        # large deployments with non-main orchestrator
        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_changed,
            self._on_peer_clusters_relation_changed_for_snapshots,
        )
        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_departed,
            self._on_peer_clusters_relation_departed_for_snapshots,
        )
        self.framework.observe(
            self.verify_backup_credentials_event, self._on_verify_backup_credentials
        )

        # actions
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_action)

    def _on_backup_credentials_changed(  # noqa C901
        self, event: Union[CredentialsChangedEvent, StorageConnectionInfoChangedEvent]
    ) -> None:
        """Handler for backup credentials changed event."""
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            logger.debug("Deployment description not ready; deferring %s", event)
            event.defer()
            return

        # block non-main orchestrators only when they are in a multi-app topology.
        if (
            deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR
            and self._is_part_of_large_deployment()
        ):
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupRelShouldNotExist), app=True)
            return

        object_storage_type = self.charm.snapshots_manager.get_storage_type()

        if not object_storage_type:
            logger.warning("No object storage type could be determined.")
            return

        if object_storage_type == ObjectStorageType.CONFLICT:
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupRelConflict), app=True)
            event.defer()
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelConflict, app=True)
            if raw := self.charm.state.app.relation_data.get(Scope.APP, "missing_relations"):
                missing_relations = [r.strip() for r in raw.split(",") if r.strip()]

                if (
                    "azure-storage-integrator" in missing_relations
                    and object_storage_type == ObjectStorageType.AZURE
                ):
                    missing_relations.remove("azure-storage-integrator")
                if (
                    "s3-integrator" in missing_relations
                    and object_storage_type == ObjectStorageType.S3
                ):
                    missing_relations.remove("s3-integrator")

                # still have others missing: update status and stored string
                if missing_relations:
                    missing_str = ", ".join(sorted(missing_relations))
                    self.charm.status.set(
                        BlockedStatus(PClusterMissingStorageRelations.format(missing_str)),
                        app=True,
                    )
                    self.charm.state.app.relation_data.put(
                        Scope.APP, "missing_relations", missing_str
                    )
                else:
                    self.charm.state.app.relation_data.delete(Scope.APP, "missing_relations")
                    self.charm.status.clear(
                        PClusterMissingStorageRelations,
                        pattern=Status.CheckPattern.Interpolated,
                        app=True,
                    )

        object_storage_config = self.charm.snapshots_manager.get_storage_config(
            object_storage_type
        )

        if (
            not object_storage_config
            or (
                object_storage_type == ObjectStorageType.S3
                and (not object_storage_config.s3 or not object_storage_config.s3.credentials)
            )
            or (
                object_storage_type == ObjectStorageType.AZURE
                and (
                    not object_storage_config.azure or not object_storage_config.azure.credentials
                )
            )
        ):
            logger.warning("No %s object storage configuration.", object_storage_type)
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupRelDataIncomplete), app=True)
            return
        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelDataIncomplete, app=True)

        if (
            object_storage_type == ObjectStorageType.AZURE
            and not verify_azure_credentials(object_storage_config)
        ) or (
            object_storage_type == ObjectStorageType.S3
            and not verify_s3_credentials(object_storage_config)
        ):
            logger.warning("%s object storage credentials not verified.", object_storage_type)
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupCredentialIncorrect), app=True)
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupCredentialIncorrect, app=True)

        if object_storage_type == ObjectStorageType.S3:
            self.charm.keystore_manager.put_entries(
                {
                    "s3.client.default.access_key": object_storage_config.s3.credentials.access_key,
                    "s3.client.default.secret_key": object_storage_config.s3.credentials.secret_key,
                }
            )

            if object_storage_config.s3.tls_ca_chain:
                if not self.charm.snapshots_manager.is_custom_s3_ca_stored(
                    object_storage_config.s3.tls_ca_chain
                ):
                    # Content differs: rotate / store new chain
                    self.charm.snapshots_manager.store_s3_ca(object_storage_config.s3.tls_ca_chain)
                    logger.info("S3 CA stored/updated.")
            else:
                self.charm.snapshots_manager.remove_s3_ca()

        elif object_storage_type == ObjectStorageType.AZURE:
            self.charm.keystore_manager.put_entries(
                {
                    "azure.client.default.account": object_storage_config.azure.credentials.storage_account,
                    "azure.client.default.key": object_storage_config.azure.credentials.secret_key,
                }
            )

        self.charm.keystore_manager.reload()

        if not self.charm.unit.is_leader():
            return

        try:
            self.charm.snapshots_manager.ensure_repository(
                object_storage_type, object_storage_config
            )
            self.verify_backup_credentials_event.emit()
        except OpenSearchHttpError as e:
            logger.error(
                "Failed to create/verify snapshot repository for %s. "
                "Error: %s, response_body=%r",
                object_storage_type,
                e,
                getattr(e, "response_body", None),
            )
            self.charm.status.set(
                BlockedStatus(
                    BackupMisconfiguration.format(
                        object_storage_type.value, f"{object_storage_type.value} integrator"
                    )
                ),
                app=True,
            )
            event.defer()
            return

        self.charm.status.clear(
            BackupMisconfiguration.format(
                object_storage_type.value, f"{object_storage_type.value} integrator"
            ),
            app=True,
        )

        self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)

    def _on_backup_credentials_gone(
        self, event: CredentialsGoneEvent | StorageConnectionInfoGoneEvent
    ) -> None:
        """Handler for s3 credentials gone event."""
        object_storage_type = (
            ObjectStorageType.S3
            if isinstance(event, CredentialsGoneEvent)
            else ObjectStorageType.AZURE
        )

        if not object_storage_type:
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelShouldNotExist, app=True)
            self.charm.status.clear(BackupRelDataIncomplete, app=True)
            self.charm.status.clear(
                BackupMisconfiguration.format(
                    object_storage_type.value, f"{object_storage_type.value} integrator"
                ),
                app=True,
            )

        keystore_entries = []
        if object_storage_type == ObjectStorageType.S3:
            keystore_entries = ["s3.client.default.access_key", "s3.client.default.secret_key"]
        elif object_storage_type == ObjectStorageType.AZURE:
            keystore_entries = ["azure.client.default.account", "azure.client.default.key"]

        if not self.charm.snapshots_manager.cleanup(
            object_storage_type=object_storage_type,
            keystore_entries=keystore_entries,
            remove_repository=True,
        ):
            logger.warning("Cleanup for %s credentials are failed.", object_storage_type)
            if self.charm.unit.is_leader():
                self.charm.status.set(
                    BlockedStatus(BackupCredentialCleanupFailed),
                    app=True,
                )
            event.defer()
            return

        if (
            object_storage_type == ObjectStorageType.S3
            and self.charm.snapshots_manager.is_custom_s3_ca_stored()
        ):
            self.charm.snapshots_manager.remove_s3_ca()

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupCredentialCleanupFailed, app=True)
            self.charm.status.clear(BackupCredentialIncorrect, app=True)

        self.charm.keystore_manager.reload()

        self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)

    def _on_peer_clusters_relation_changed_for_snapshots(self, event) -> None:  # noqa C901
        """Apply snapshots config when the orchestrator broadcasts over peer-clusters."""
        if not self.charm.opensearch_peer_cm.deployment_desc():
            logger.debug("Deployment description not ready; deferring %s", event)
            event.defer()
            return

        # Read peer data
        s3_info = self._read_s3_from_peer_cluster_rel()
        azure_info = self._read_azure_from_peer_cluster_rel()

        # check conflict
        if s3_info and azure_info:
            logger.error(
                "Received both S3 and Azure snapshot credentials over peer-clusters. "
                "This is a conflict, not applying any object-storage config."
            )
            return

        info_to_save = s3_info if s3_info else azure_info
        object_storage_type_to_clean = ObjectStorageType.AZURE if s3_info else ObjectStorageType.S3
        keystore_entries_to_clean = (
            [
                "azure.client.default.account",
                "azure.client.default.key",
            ]
            if s3_info
            else [
                "s3.client.default.access_key",
                "s3.client.default.secret_key",
            ]
        )
        # only S3 provided: clean Azure, configure S3
        if info_to_save:
            # clean Azure keys from keystore.
            if not self.charm.snapshots_manager.cleanup(
                object_storage_type=object_storage_type_to_clean,
                keystore_entries=keystore_entries_to_clean,
            ):
                if self.charm.unit.is_leader():
                    self.charm.status.set(
                        BlockedStatus(BackupCredentialCleanupFailed),
                        app=True,
                    )
                event.defer()
                return

            if self.charm.unit.is_leader():
                self.charm.status.clear(BackupCredentialCleanupFailed, app=True)

            # apply credentials
            if s3_info:
                self.charm.keystore_manager.put_entries(
                    {
                        "s3.client.default.access_key": s3_info["access_key"],
                        "s3.client.default.secret_key": s3_info["secret_key"],
                    }
                )
            elif azure_info:
                self.charm.keystore_manager.put_entries(
                    {
                        "azure.client.default.account": azure_info["storage_account"],
                        "azure.client.default.key": azure_info["secret_key"],
                    }
                )

            # Optional CA chain
            if s3_info and s3_info.get("s3_tls_ca_chain"):
                logger.info("S3 TLS CA Chain detected.")
                self.charm.snapshots_manager.store_s3_ca(s3_info["s3_tls_ca_chain"])

            elif self.charm.snapshots_manager.is_custom_s3_ca_stored():
                # If we had a custom CA but peer no longer provides one, clean it up
                self.charm.snapshots_manager.remove_s3_ca()

            self.charm.keystore_manager.reload()
            logger.info("%s credentials are added to keystore.", "S3" if s3_info else "Azure")
            self.charm.snapshots_manager.set_credentials_saved(info_to_save)
            return

        # neither S3 nor Azure provided: clean everything.
        logger.info(
            "No snapshot backend credentials received from peer-clusters"
            "cleaning all object-storage snapshot configuration."
        )

        # clean S3-related config
        self.charm.snapshots_manager.cleanup(
            object_storage_type=ObjectStorageType.S3,
            keystore_entries=[
                "s3.client.default.access_key",
                "s3.client.default.secret_key",
            ],
        )

        # clean Azure-related config
        self.charm.snapshots_manager.cleanup(
            object_storage_type=ObjectStorageType.AZURE,
            keystore_entries=[
                "azure.client.default.account",
                "azure.client.default.key",
            ],
        )

        # clean S3 CA
        if self.charm.snapshots_manager.is_custom_s3_ca_stored():
            self.charm.snapshots_manager.remove_s3_ca()

        self.charm.keystore_manager.reload()
        self.charm.snapshots_manager.set_credentials_saved(None)

    def _on_peer_clusters_relation_departed_for_snapshots(self, event) -> None:  # noqa C901
        """Cleanup snapshot config if the orchestrator we depended on is gone."""
        if not self.charm.opensearch_peer_cm.deployment_desc():
            logger.debug("Deployment description not ready; deferring %s", event)
            event.defer()
            return

        if (
            self.charm.state.app.orchestrators
            and self.charm.state.app.orchestrators.main_app
            and self.charm.state.app.orchestrators.main_app.name == event.relation.app.name
            and len(event.relation.units) > 0
        ):
            logger.debug(
                "Main orchestrator still accessible; do not cleanup as it can be scale down"
            )
            return

        logger.info(
            "peer-clusters relation for snapshots departed; "
            "cleaning all object-storage snapshot configuration."
        )

        # clean S3-related config
        if not self.charm.snapshots_manager.cleanup(
            object_storage_type=ObjectStorageType.S3,
            keystore_entries=[
                "s3.client.default.access_key",
                "s3.client.default.secret_key",
            ],
        ):
            if self.charm.unit.is_leader():
                self.charm.status.set(
                    BlockedStatus(BackupCredentialCleanupFailed),
                    app=True,
                )
            event.defer()
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupCredentialCleanupFailed, app=True)

        # clean Azure-related config
        if not self.charm.snapshots_manager.cleanup(
            object_storage_type=ObjectStorageType.AZURE,
            keystore_entries=[
                "azure.client.default.account",
                "azure.client.default.key",
            ],
        ):
            if self.charm.unit.is_leader():
                self.charm.status.set(
                    BlockedStatus(BackupCredentialCleanupFailed),
                    app=True,
                )
            event.defer()
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupCredentialCleanupFailed, app=True)

        # clean S3 CA if it was stored
        if self.charm.snapshots_manager.is_custom_s3_ca_stored():
            self.charm.snapshots_manager.remove_s3_ca()

        self.charm.keystore_manager.reload()

    def _on_verify_backup_credentials(self, event: VerifyBackupCredentialsEvent) -> None:
        """Verify that stored backup credentials are still valid."""
        credential_dict = {}
        object_storage_type = self.charm.snapshots_manager.get_storage_type()
        object_storage_config = self.charm.snapshots_manager.get_storage_config(
            object_storage_type
        )

        if not object_storage_type or not object_storage_config:
            return

        if object_storage_config.s3:
            credential_dict = {
                "access_key": object_storage_config.s3.credentials.access_key,
                "secret_key": object_storage_config.s3.credentials.secret_key,
                "s3_tls_ca_chain": object_storage_config.s3.tls_ca_chain,
            }
        elif object_storage_config.azure:
            credential_dict = {
                "storage_account": object_storage_config.azure.credentials.storage_account,
                "secret_key": object_storage_config.azure.credentials.secret_key,
            }

        credentials_hash = self.charm.snapshots_manager.hash_credentials(credential_dict)

        # check all other clusters if they have saved the credentials
        all_relation_ids = [
            rel.id
            for rel in self.charm.model.relations[PeerClusterOrchestratorRelationName]
            if len(rel.units) > 0
        ]

        for rel_id in all_relation_ids:
            relation = self.charm.model.get_relation(PeerClusterOrchestratorRelationName, rel_id)
            for unit in relation.units:
                rel_data = relation.data.get(unit)
                if not rel_data:
                    continue
                saved_hash = rel_data.get("credentials_saved")
                if saved_hash != credentials_hash:
                    logger.warning(
                        "Unit %s in relation %s has not saved the latest backup credentials.",
                        unit.name,
                        rel_id,
                    )
                    event.defer()
                    return

        # all units have saved the latest credentials
        logger.info("All peer-cluster units have saved the latest backup credentials.")
        try:
            self.charm.snapshots_manager.verify_repository(object_storage_type)
        except OpenSearchHttpError as e:
            self.charm.status.set(
                BlockedStatus(
                    BackupMisconfiguration.format(
                        object_storage_type.value, f"{object_storage_type.value} integrator"
                    )
                ),
                app=True,
            )
            logger.error(
                "Failed to verify snapshot repository after credentials verification. "
                "Error: %s, response_body=%r",
                e,
                getattr(e, "response_body", None),
            )
            event.defer()
            return
        self.charm.status.clear(
            BackupMisconfiguration.format(
                object_storage_type.value, f"{object_storage_type.value} integrator"
            ),
            app=True,
        )
        logger.info("Backup credentials verified successfully.")

    def _get_provider_rel_payload(self) -> PeerClusterRelData | None:  # noqa: C901
        """Return the payload from the main orchestrator relation, if any."""
        try:
            data_str = self.charm.opensearch_peer_cm.get_rel_data_from_main_orchestrator()
        except Exception as e:
            logger.warning("failed to get relation data: %s", e)
            return None

        if not data_str:
            logger.info("no rel payload found on %s", PeerClusterOrchestratorRelationName)
            return None

        try:
            payload = self.charm.opensearch_peer_cm.rel_data_from_str(data_str)
        except Exception as e:
            logger.warning("failed to parse relation data: %s", e)
            return None

        logger.info("provided %s payload", PeerClusterOrchestratorRelationName)
        return payload

    def _read_s3_from_peer_cluster_rel(self) -> dict[str, str] | None:
        payload = self._get_provider_rel_payload()
        if not payload or not payload.credentials or not payload.credentials.s3:
            logger.warning("no S3 credentials found.")
            return

        if not (payload.credentials.s3.access_key and payload.credentials.s3.secret_key):
            logger.warning("no access key or secret key found.")
            return

        # CA chain may be published separately
        logger.debug("S3 CA secret: %s", payload.credentials.s3.s3_tls_ca_chain)
        return {
            "access_key": payload.credentials.s3.access_key,
            "secret_key": payload.credentials.s3.secret_key,
            "s3_tls_ca_chain": payload.credentials.s3.s3_tls_ca_chain,
        }

    def _read_azure_from_peer_cluster_rel(self) -> dict[str, str] | None:
        payload = self._get_provider_rel_payload()
        if not payload or not payload.credentials or not payload.credentials.azure:
            logger.warning("no azure credentials found.")
            return

        if not (
            payload.credentials.azure.storage_account and payload.credentials.azure.secret_key
        ):
            logger.debug("Azure storage credentials are incomplete.")
            return

        return {
            "storage_account": payload.credentials.azure.storage_account,
            "secret_key": payload.credentials.azure.secret_key,
        }

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handler for s3 create backup action event."""
        if error_message := self._action_missing_pre_requisites():
            event.fail(error_message)
            return

        self.charm.status.set(MaintenanceStatus(BackupInProgress))
        try:
            object_storage_type = self.charm.snapshots_manager.get_storage_type()
            # Create a new snapshot
            try:
                snapshot_id = self.charm.snapshots_manager.create_snapshot(
                    object_storage_type=object_storage_type,
                )
            except OpenSearchHttpError as e:
                logger.error("Could not create a new snapshot: %s", e)
                event.fail(f"Backup request failed with: {str(e)}")
                return

            # Fetch the new snapshot for sanity check
            try:
                snapshot = self.charm.snapshots_manager.get_snapshot(
                    object_storage_type=object_storage_type, snapshot_id=snapshot_id
                )
                status = str(snapshot.get("state", "unknown")).lower()
                event.set_results({"backup-id": snapshot_id, "status": status})
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
            object_storage_type = self.charm.snapshots_manager.get_storage_type()
            snapshots = self.charm.snapshots_manager.list_snapshots(
                object_storage_type=object_storage_type
            )
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

        self.charm.status.set(MaintenanceStatus(RestoreInProgress))
        try:
            object_storage_type = self.charm.snapshots_manager.get_storage_type()
            # Fetch the snapshot with the corresponding ID
            try:
                if not (
                    snapshot := self.charm.snapshots_manager.get_snapshot(
                        object_storage_type, snapshot_id
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
            logger.info("Starting restore of snapshot %s.", snapshot_id)
            try:
                non_restored_indices = self.charm.snapshots_manager.restore_snapshot(
                    object_storage_type=object_storage_type, snapshot=snapshot
                )
                if not non_restored_indices:
                    final_status = self.charm.health.apply(
                        wait_for_green_first=True, app=self.charm.unit.is_leader()
                    )
                    if final_status == "green":
                        event.set_results({"restored-backup-id": snapshot_id, "status": "success"})
                    else:
                        event.set_results(
                            {
                                "restored-backup-id": snapshot_id,
                                "status": "success_with_warning",
                                "note": "restore completed; cluster didn't reach GREEN within 30s",
                            }
                        )
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

    def _action_missing_pre_requisites(  # noqa C901
        self, report_running_operations: bool = True
    ) -> str | None:
        """Compute the missing prerequisites for running a snapshot/restore action.

        Args:
            report_running_operations (bool): Whether to report running operations.

        Returns:
            A string representing the missing prerequisites.
        """
        if not self.charm.unit.is_leader():
            return "Backup/Restore related actions must be run on the juju leader unit."

        if not self.charm.opensearch_peer_cm.deployment_desc():
            return "Deployment not ready."

        if self.charm.upgrade_in_progress:
            return "Backup/Restore operations not supported while upgrade in-progress."

        object_storage_type = self.charm.snapshots_manager.get_storage_type()

        if not object_storage_type:
            if self.charm.unit.is_leader():
                for msg in (
                    BackupCredentialIncorrect,
                    BackupRelConflict,
                    BackupRelDataIncomplete,
                ):
                    self.charm.status.set(BlockedStatus(msg), app=True)
            return "Missing relation with an object storage integrator."

        if object_storage_type == ObjectStorageType.CONFLICT:
            return "Conflict: more than one object storage integrators integrated."

        if not self.charm.opensearch.is_node_up() and not self.charm.alt_hosts:
            return "Connectivity issue: the opensearch service is not reachable."

        repo_name = self.charm.snapshots_manager.repository_name(object_storage_type)
        logger.debug(
            f"[snapshots] precheck: type={object_storage_type} repo={repo_name} alt_hosts={self.charm.alt_hosts}"
        )

        pcluster_types = {"s3-pcluster", "azure-pcluster", "gcs-pcluster"}
        if object_storage_type not in pcluster_types:
            try:
                if not self.charm.snapshots_manager.get_storage_config():
                    return "Object storage configuration not ready."
                if not self.charm.snapshots_manager.is_repository_created(object_storage_type):
                    return "The opensearch repository could not be created yet."
            except OpenSearchHttpError as e:
                return f"Action failed with: {str(e)}."

        if not report_running_operations:
            return

        match self.charm.health.get(wait_for_green_first=True):
            case HealthColors.RED:
                return "Cluster health red, current state must be resolved before."
            case HealthColors.YELLOW_TEMP:
                return "Shards are still relocating or initializing."
            case HealthColors.UNKNOWN:
                return "Cluster health unknown."

        try:
            if (
                self.charm.snapshots_manager.is_snapshot_in_progress()
                or self.charm.snapshots_manager.is_restore_in_progress()
            ):
                return "Backup / Restore operation in progress."
        except OpenSearchHttpError as e:
            return f"Action failed with: {str(e)}."

        return

    def _is_part_of_large_deployment(self) -> bool:
        """Return True if this app participates in a multi-app topology (main/failover/data)."""
        return (
            self.charm.opensearch_peer_cm.is_provider()
            or self.charm.opensearch_peer_cm.is_consumer()
        )


class OpenSearchSnapshotsManager:
    """Manager class for Backups (snapshots)."""

    def __init__(self, charm: "OpenSearchBaseCharm", opensearch: "OpenSearchDistribution"):
        self.charm = charm  # todo this will need to be replaced by the clusterState
        self.opensearch = opensearch

    def get_storage_type(self) -> Optional[ObjectStorageType]:  # noqa: C901
        """Get the active object storage type from relations/peer-cluster.

        Returns:
            Optional[ObjectStorageType]: the active object storage type.
        """
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            logger.debug("Deployment description missing; storage type unknown.")
            return None

        if deployment_desc.typ in {DeploymentType.MAIN_ORCHESTRATOR}:
            active = [
                r
                for r in [
                    self.charm.model.get_relation(S3_RELATION),
                    self.charm.model.get_relation(AZURE_RELATION),
                    self.charm.model.get_relation(GCS_RELATION),
                ]
                if r
            ]
            if len(active) == 0:
                return None
            if len(active) > 1:
                return ObjectStorageType.CONFLICT
            if self.charm.model.get_relation(S3_RELATION):
                return ObjectStorageType.S3
            if self.charm.model.get_relation(AZURE_RELATION):
                return ObjectStorageType.AZURE
            if self.charm.model.get_relation(GCS_RELATION):
                return ObjectStorageType.GCS

        # non-main orchestrator
        peer_data = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        if not peer_data or not peer_data.credentials:
            return None
        if peer_data.credentials.s3:
            return ObjectStorageType.S3_PCLUSTER
        if peer_data.credentials.azure:
            return ObjectStorageType.AZURE_PCLUSTER
        if peer_data.credentials.gcs:
            return ObjectStorageType.GCS_PCLUSTER

    def get_storage_config(  # noqa: C901
        self, forced_storage_type: Optional[ObjectStorageType] = None
    ) -> Optional[ObjectStorageConfig]:
        """Get the active object storage config from relations/peer-cluster.

        Args:
            forced_storage_type (Optional[ObjectStorageType]):
                force the type of the config to return.

        Returns:
            ObjectStorageConfig | None: the active object storage config.
        """
        object_storage_type = forced_storage_type or self.get_storage_type()
        if not object_storage_type or object_storage_type == ObjectStorageType.CONFLICT:
            return

        if object_storage_type == ObjectStorageType.S3:
            # TODO: Do not get data from the events
            info = self.charm.snapshot_events.s3_requirer.get_s3_connection_info()

            try:
                s3 = S3RelData.from_relation(info) if info else None
            except ValidationError as e:
                logger.warning("validation error while building s3 payload: %s", e)
                s3 = None
            return ObjectStorageConfig(s3=s3) if s3 else None

        if object_storage_type == ObjectStorageType.AZURE:
            # TODO: Do not get data from the events
            info = self.charm.snapshot_events.azure_requirer.get_azure_storage_connection_info()
            try:
                azure = AzureRelData.from_relation(info) if info else None
            except ValidationError as e:
                logger.warning("validation error while building azure payload: %s", e)
                azure = None
            return ObjectStorageConfig(azure=azure) if azure else None

        if object_storage_type == ObjectStorageType.GCS:
            # TODO: implement this
            return

        peer_data = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        if object_storage_type == ObjectStorageType.S3_PCLUSTER:
            if not peer_data or not peer_data.credentials or not peer_data.credentials.s3:
                return None
            return ObjectStorageConfig(s3=peer_data.credentials.s3)

        if object_storage_type == ObjectStorageType.AZURE_PCLUSTER:
            if not peer_data or not peer_data.credentials or not peer_data.credentials.azure:
                return None
            return ObjectStorageConfig(azure=peer_data.credentials.azure)

        if object_storage_type == ObjectStorageType.GCS_PCLUSTER:
            if not peer_data or not peer_data.credentials or not peer_data.credentials.gcs:
                return None
            return ObjectStorageConfig(gcs=peer_data.credentials.gcs)

        return

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def create_repository(
        self,
        object_storage_type: ObjectStorageType,
        object_storage_config: ObjectStorageConfig,
        name: str | None = None,
    ) -> str | None:
        """Create an opensearch repository for storing backups.

        Args:
            object_storage_type (ObjectStorageType): Object storage type
            object_storage_config (ObjectStorageConfig): Object storage config
            name (str, optional): Name of the repository. Defaults to None.

        Returns:
            str: Repository name
        """
        repository_name = name or self.repository_name(object_storage_type)
        settings = {}
        if object_storage_type == ObjectStorageType.S3:
            settings = {
                "bucket": object_storage_config.s3.bucket,
                "base_path": object_storage_config.s3.base_path,
                "region": object_storage_config.s3.region,
                "endpoint": object_storage_config.s3.endpoint,
            }

        elif object_storage_type == ObjectStorageType.AZURE:
            settings = {
                "container": object_storage_config.azure.container,
                "base_path": object_storage_config.azure.base_path,
            }
        elif object_storage_type == ObjectStorageType.GCS:
            settings = {
                "bucket": object_storage_config.gcs.bucket,
                "base_path": object_storage_config.gcs.base_path,
            }

        repo_type = self._repo_type(object_storage_type)
        response = self.opensearch.request(
            "PUT",
            f"_snapshot/{repository_name}?verify=false",
            payload={"type": repo_type, "settings": settings},
        )
        logger.debug("Snapshot repository creation response: %s", response)

        # This should always pass and is set for documentation purposes
        assert response.get("acknowledged") is True
        return repository_name

    def ensure_repository(
        self, storage_type: ObjectStorageType, storage_cfg: ObjectStorageConfig
    ) -> bool:
        """Create the repository if we have a storage type/config and it doesn't exist yet.

        Args:
            storage_type (ObjectStorageType): Object storage type
            storage_cfg (ObjectStorageConfig): Object storage config

        Raises:
            OpenSearchHttpError: repository does not exist
        """
        if not storage_type or not storage_cfg or storage_type == ObjectStorageType.CONFLICT:
            return False

        if storage_type not in {
            ObjectStorageType.S3,
            ObjectStorageType.AZURE,
            ObjectStorageType.GCS,
        }:
            logger.error("Repository should be created by main orchestrator.")
            return False

        logger.info("Creating/Updating snapshot repository for %s", storage_type)
        self.create_repository(
            object_storage_type=storage_type,
            object_storage_config=storage_cfg,
        )
        logger.info("Created/Updated snapshot repository for %s", storage_type)
        return self.is_repository_created(storage_type)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def remove_repository(
        self,
        object_storage_type: ObjectStorageType,
        name: str | None = None,
    ) -> None:
        """Remove the snapshot repository with retries and optional health gating.

        Args:
            object_storage_type: Object storage type to use
            name: Name of the repository to remove
        """
        repo_name = name or self.repository_name(object_storage_type)

        try:
            resp = self.opensearch.request(
                "DELETE", f"_snapshot/{repo_name}", alt_hosts=self.charm.alt_hosts
            )
            assert resp.get("acknowledged") is True
        except OpenSearchHttpError as e:
            body = e.response_body or {}
            err_type = (
                (body.get("error") or {}).get("type") if isinstance(body, dict) else str(body)
            )
            if "repository_missing_exception" in str(err_type):
                return
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def create_snapshot(self, object_storage_type: ObjectStorageType) -> str:
        """Create an OpenSearch snapshot.

        Args:
            object_storage_type: Object storage type to use

        Returns:
            snapshot_id: Snapshot ID
        """
        repo_name = self.repository_name(object_storage_type)
        snapshot_id = datetime.now().strftime(OPENSEARCH_BACKUP_ID_FORMAT).lower()
        ignore = [f"-{idx}" for idx in SYSTEM_INDICES]
        indices_clause = ",".join(["*"] + ignore)
        logger.info("indices_clause: %s", indices_clause)
        # create snapshot
        response = self.opensearch.request(
            "PUT",
            f"_snapshot/{repo_name}/{snapshot_id}?wait_for_completion=false",
            payload={
                "indices": indices_clause,
                "ignore_unavailable": True,
                "include_global_state": True,
            },
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
        """Restore an OpenSearch snapshot.

        Args:
            object_storage_type: Object storage type to use
            snapshot: Snapshot to restore

        Returns:
            Empty set if snapshot was restored else set includes not restored indices
        """
        repo_name = self.repository_name(object_storage_type)
        snapshot_id = snapshot.get("snapshot")
        ignore = [f"-{idx}" for idx in SYSTEM_INDICES]
        indices_clause = ",".join(["*"] + ignore)

        payload = {
            "indices": indices_clause,
            "ignore_unavailable": True,
            "include_global_state": False,
        }

        restore_resp = self.opensearch.request(
            "POST",
            f"_snapshot/{repo_name}/{snapshot_id}/_restore?wait_for_completion=true",
            payload=payload,
            alt_hosts=self.charm.alt_hosts,
            timeout=60,
        )
        logger.info("Restore of snapshot '%s' response: %s", snapshot_id, restore_resp)

        # this only serves as documentation and should always be true if no previous HTTP error
        snapshot_field = restore_resp.get("snapshot")
        assert "accepted" in restore_resp or (
            isinstance(snapshot_field, dict) and snapshot_field.get("snapshot") == snapshot_id
        ), f"Unexpected restore response: {restore_resp}"

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
        """Close the non-system indices included in a given snapshot.

        Args:
            snapshot (dict): Snapshot to close.

        Returns:
            Tuple: closed_indices, failed_to_closed_indices
        """
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
        """Fetch the current open indices in the current cluster.

        Args:
            snapshot (dict): Snapshot information

        Returns:
            list[str] | None: List of indices which are open
        """
        current_indices = ClusterState.indices(self.charm.opensearch)
        return sorted(
            [
                idx
                for idx in snapshot.get("indices", [])
                if idx in current_indices
                and idx not in SYSTEM_INDICES
                and current_indices[idx]["status"] == "open"
            ]
        )

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def get_snapshot(
        self, object_storage_type: ObjectStorageType, snapshot_id: str
    ) -> dict[str, Any] | None:
        """Fetch a snapshot by id.

        Args:
            object_storage_type (ObjectStorageType): Object storage type.
            snapshot_id (str): Snapshot id.

        Returns:
            dict[str, Any] | None: Snapshot information.
        """
        repo_name = self.repository_name(object_storage_type)
        try:
            response = self.opensearch.request(
                "GET", f"_snapshot/{repo_name}/{snapshot_id}", alt_hosts=self.charm.alt_hosts
            )
            return response["snapshots"][0]
        except OpenSearchHttpError as e:
            if e.response_body.get("error", {}).get("type") == "snapshot_missing_exception":
                return
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def list_snapshots(self, object_storage_type: ObjectStorageType) -> dict[Any, dict[str, Any]]:
        """List all snapshots in the current repository.

        Args:
            object_storage_type (ObjectStorageType): Object storage type.

        Returns:
            dict: Snapshot information.
        """
        repo_name = self.repository_name(object_storage_type)
        response = self.opensearch.request(
            "GET",
            f"_snapshot/{repo_name}/_all",
            alt_hosts=self.charm.alt_hosts,
            timeout=30,
        )
        snapshots = {
            snapshot["snapshot"]: {
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
        """Check if a repository is created.

        Args:
            object_storage_type (ObjectStorageType): Object storage type.
            repository (str): The name of the repository to check.

        Returns:
            True if repository is created else False
        """
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
    def is_snapshot_in_progress(self) -> bool:
        """Check if a backup is running.

        Returns:
            True if snapshot is running else False
        """
        response = self.opensearch.request(
            "GET", "_snapshot/_status", alt_hosts=self.charm.alt_hosts
        )
        return len(response.get("snapshots", [])) > 0

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def is_restore_in_progress(self) -> bool:
        """Check if a restore operation is running.

        Returns:
            True if restore operation is running else False
        """
        response: list[dict[str, str]] = self.opensearch.request(
            "GET", "/_cat/recovery?format=json&h=type,stage", alt_hosts=self.charm.alt_hosts
        )
        for operation in response:
            if operation["type"] == "snapshot" and operation["stage"] == "open":
                return True
        return False

    @staticmethod
    def repository_name(object_storage_type: ObjectStorageType) -> str | None:
        """Get the repository name for a given storage type.

        Args:
            object_storage_type: Object storage type

        Returns:
            repository name
        """
        if object_storage_type in {"s3", "s3-pcluster"}:
            return S3_REPOSITORY

        if object_storage_type in {"azure", "azure-pcluster"}:
            return AZURE_REPOSITORY

        return GCS_REPOSITORY

    def find_s3_chain_in_store(self) -> str:
        """Return the currently stored S3 CA chain from cacerts, or ''.

        Returns:
            Stored CA chain if found, else ''.
        """
        stored_cacerts = list_cas(
            store_pwd=STORE_PASSWORD,
            store_path=f"{self.opensearch.paths.certs}/cacerts.p12",
        )

        if not stored_cacerts:
            return ""
        # list_cas consolidates per base alias, so we just look up the root alias
        chain = stored_cacerts.get(S3_CA_ALIAS, "")
        return chain or ""

    def is_custom_s3_ca_stored(self, s3_ca_chain: str | None = None) -> bool:
        """Check if a custom CA for the object storage is stored in the cacerts trust store.

        Args:
            s3_ca_chain: CA chain which will be detected in the stored cacerts

        Returns:
            True if the given CA chain is stored in the stored cacerts, else False
        """
        current_chain = self.find_s3_chain_in_store()
        if not current_chain:
            # Nothing stored at all: definitely no custom S3 CA
            return False

        if not s3_ca_chain:
            # There is existing S3 CA stored, but no new one, we need to remove the old one.
            return True

        # Compare as unordered sets of normalized cert blocks
        stored_blocks = normalize_certificate_chain_unordered(current_chain)
        new_blocks = normalize_certificate_chain_unordered(s3_ca_chain)

        return stored_blocks == new_blocks

    def remove_s3_ca(self) -> None:
        """Remove an S3 TLS CA chain on the cacerts trust store.

        Args:
            s3_tls_ca_chain: S3 TLS CA chain to remove
        """
        store_path = f"{self.opensearch.paths.certs}/cacerts.p12"
        # Drop the CA entirely
        remove_s3_ca(
            alias=S3_CA_ALIAS,
            store_pwd=STORE_PASSWORD,
            store_path=store_path,
        )

    def store_s3_ca(self, s3_tls_ca_chain: str | None) -> None:
        """Store or remove an S3 TLS CA chain on the cacerts trust store.

        Args:
            s3_tls_ca_chain: S3 TLS CA chain to store

        If there is s3_tls_ca_chain, the old CA will be removed.
        """
        store_path = f"{self.opensearch.paths.certs}/cacerts.p12"

        # If we already have the same CA, skip re-import
        if self.is_custom_s3_ca_stored(s3_tls_ca_chain):
            logger.info("S3 CA unchanged; skipping re-import.")
            return

        # Chain changed: ensure we remove the old alias family first
        # to avoid keytool already exists error
        remove_s3_ca(
            alias=S3_CA_ALIAS,
            store_pwd=STORE_PASSWORD,
            store_path=store_path,
        )

        # Import fresh CA
        store_s3_ca(
            store_pwd=STORE_PASSWORD,
            store_path=store_path,
            alias=S3_CA_ALIAS,
            ca=s3_tls_ca_chain,
            keep_previous=False,
        )

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def cleanup_keystore(self, object_storage_type, keystore_entries) -> None:
        """Remove keystore entries for the given object storage type with retries.

        Args:
            object_storage_type: Object storage type to use
            keystore_entries: Keystore entries to remove

        Retries on OpenSearchCmdError unless the error indicates the entries
        do not exist.
        """
        try:
            self.charm.keystore_manager.remove_entries(keystore_entries)
            self.charm.keystore_manager.reload()
            logger.info("Removed keystore entries for %s", object_storage_type)
        except OpenSearchCmdError as e:
            parts = [
                getattr(e, "stdout", "") or "",
                getattr(e, "stderr", "") or "",
                str(e) or "",
            ]
            msg = " ".join(parts).lower()
            if "does not exist" in msg and "keystore" in msg:
                # treat as successful cleanup
                logger.info(
                    "Keystore entries already absent for %s (message: %s).",
                    object_storage_type,
                    msg,
                )
                return

            logger.warning(
                "Keystore cleanup attempt failed for %s: %s",
                object_storage_type,
                msg or repr(e),
            )
            raise

    def cleanup(
        self, object_storage_type, keystore_entries, remove_repository: bool = False
    ) -> bool:
        """Cleanup object storage config.

        Args:
            object_storage_type (str): Object storage type
            keystore_entries (list): List of keystore entries
            remove_repository (bool, optional): Remove repository entries. Defaults to False.

        Returns:
            True if all the cleanup is successful, False otherwise
        """
        if keystore_entries:
            try:
                self.cleanup_keystore(object_storage_type, keystore_entries)
            except OpenSearchCmdError as e:
                logger.warning(
                    "Keystore cleanup for %s failed after retries: %s",
                    object_storage_type,
                    e,
                )
                return False

        if remove_repository:
            if not self.charm.unit.is_leader():
                return True
            try:
                self.remove_repository(
                    object_storage_type=object_storage_type,
                )
            except OpenSearchHttpError as e:
                logger.error(
                    "Repository cleanup for %s failed after 3 attempts: %s",
                    object_storage_type,
                    e,
                )
                return False

        return True

    @staticmethod
    def _repo_type(object_storage_type: ObjectStorageType) -> str | None:
        """Return the repository type for a given object storage type.

        Args:
            object_storage_type (ObjectStorageType): The object storage type.

        Returns:
            repository_type
        """
        if object_storage_type in {"s3", "s3-pcluster"}:
            return "s3"
        if object_storage_type in {"azure", "azure-pcluster"}:
            return "azure"
        if object_storage_type in {"gcs", "gcs-pcluster"}:
            return "gcs"

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def verify_repository(self, object_storage_type: ObjectStorageType) -> bool:
        """Verify repository by listing snapshots.

        Args:
            object_storage_type (ObjectStorageType): Object storage type

        Returns:
            True if the repository can be listed successfully.

        Raises:
            OpenSearchHttpError if there are any backend issues such as auth/perm errors.
        """
        repository = self.repository_name(object_storage_type)
        # If creds/endpoint/perm are wrong, this call raises OpenSearchHttpError with a 500.
        self.opensearch.request(
            "GET",
            f"_snapshot/{repository}/_all",
            alt_hosts=self.charm.alt_hosts,
            timeout=30,
        )
        return True

    def set_credentials_saved(self, credentials: dict[str, str] | None) -> None:
        """Set in the peer relation data that credentials have been saved."""
        orchestrators = self.charm.state.app.orchestrators

        if not orchestrators or orchestrators.main_app is None:
            return

        # set the credentials_saved in the unit data bag with the main orchestrator
        relation = self.charm.model.get_relation(
            PeerClusterRelationName, orchestrators.main_rel_id
        )

        if not relation:
            logger.warning("No peer-cluster relation found to set credentials_saved.")
            return

        if credentials is None:
            relation.data[self.charm.unit].pop("credentials_saved", None)
            return

        relation.data[self.charm.unit].update(
            {
                "credentials_saved": self.hash_credentials(credentials),
            }
        )

    def hash_credentials(self, credentials: dict[str, str]) -> str:
        """Return a hash of the given credentials."""
        return hashlib.sha1(json.dumps(credentials, sort_keys=True).encode()).hexdigest()
