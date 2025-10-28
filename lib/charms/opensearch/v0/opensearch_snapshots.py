# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Snapshots."""

import json
import logging
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, Iterable, List, Optional, Tuple

from charms.data_platform_libs.v0.azure_storage import (
    AzureStorageRequires,
    StorageConnectionInfoChangedEvent,
    StorageConnectionInfoGoneEvent,
)
from charms.data_platform_libs.v0.data_interfaces import Scope
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
    PeerClusterOrchestratorRelationName,
    PeerClusterRelationName,
    RestoreInProgress,
)
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.helper_security import list_cas, remove_ca, store_s3_ca
from charms.opensearch.v0.helper_storage import ObjectStorageResolver, ObjectStorageType
from charms.opensearch.v0.models import (
    AzureRelData,
    DeploymentType,
    GcsRelData,
    ObjectStorageConfig,
    S3RelData,
)
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_locking import OpenSearchNodeLock
from ops import (
    ActionEvent,
    BlockedStatus,
    MaintenanceStatus,
    Object,
    Secret,
)
from ops.framework import EventBase, EventSource
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
OS_PEER_KEY_TYPE = "object-storage-type"
OS_PEER_KEY_REPO = "object-storage-repo"


# System indices that should not be snapshotted
SYSTEM_INDICES = {
    ".opendistro_security",
    OpenSearchNodeLock.OPENSEARCH_INDEX,
}

SKIP_ON_RESTORE = {
    ".plugins-ml-config",
    ".opensearch-sap-log-types-config",
    "top-queries",
}


class _ObjectStorageEvent(EventBase):
    def __init__(self, handle, *, kind: str, action: str):
        super().__init__(handle)
        self.kind = kind  # "s3" | "azure"
        self.action = action  # "changed" | "gone"

    def snapshot(self):
        return {"kind": self.kind, "action": self.action}

    def restore(self, snap):
        self.kind = snap["kind"]
        self.action = snap["action"]


class _ObjectStorageChanged(_ObjectStorageEvent):
    pass


class _ObjectStorageGone(_ObjectStorageEvent):
    pass


class OpenSearchSnapshotsEvents(Object):
    """Events class for Backups (snapshots)."""

    object_storage_changed = EventSource(_ObjectStorageChanged)
    object_storage_gone = EventSource(_ObjectStorageGone)

    def __init__(
        self, charm: "OpenSearchBaseCharm", resolver: ObjectStorageResolver | None = None
    ):
        super().__init__(charm, key="backups")
        self.charm = charm
        self._resolver = resolver or ObjectStorageResolver(charm)

        # requirers
        self.s3_requirer = S3Requirer(charm, S3_RELATION)
        self.azure_requirer = AzureStorageRequires(charm, AZURE_RELATION)
        self.gcs_requirer = AzureStorageRequires(charm, GCS_RELATION)

        # simple deployments or main orchestrator
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
        self.framework.observe(
            self.object_storage_changed, self._on_object_storage_changed_on_peers
        )
        self.framework.observe(self.object_storage_gone, self._on_object_storage_gone_on_peers)

        # actions
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_action)

    def _on_s3_credentials_changed(self, event: CredentialsChangedEvent) -> None:
        """Handler for s3 credentials changed event."""
        object_storage_type = self._resolver.get_storage_type() or "s3"
        logger.info(f"S3 credentials changed for object storage type {object_storage_type}")

        if object_storage_type == "conflict":
            self.charm.status.set(BlockedStatus("More than 1 object storage relation"))
            event.defer()
            return

        # handle case where this was deferred in the above case, then the s3 relation was severed
        if (
            object_storage_type != "s3"
            or not self._resolver.get_storage_config("s3")
            or not self._resolver.get_storage_config("s3").s3.credentials
        ):
            logger.warning("No S3 object storage configuration.")
            return

        # apply locally (leader does cluster-level config)
        self.charm.keystore_manager.put_entries(
            {
                "s3.client.default.access_key": self._resolver.get_storage_config(
                    "s3"
                ).s3.credentials.access_key,
                "s3.client.default.secret_key": self._resolver.get_storage_config(
                    "s3"
                ).s3.credentials.secret_key,
            }
        )
        logger.info("S3 credentials are added to keystore.")
        self.charm.keystore_manager.reload()

        if self.charm.snapshots_manager.requires_custom_s3_ca(
            object_storage_type, self._resolver.get_storage_config("s3")
        ):
            self.charm.snapshots_manager.store_s3_ca(
                self._resolver.get_storage_config("s3").s3.tls_ca_chain
            )
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
                object_storage_config=self._resolver.get_storage_config("s3"),
            )
            logger.info("service should be restarted")
        except OpenSearchHttpError as e:
            logger.warning("Skip restart precheck (OpenSearch not ready?): %s", e)
            need_restart = False

        if need_restart:
            self.charm.request_opensearch_restart(reason="apply new object storage CA")
        self._ensure_repository(object_storage_type, self._resolver.get_storage_config("s3"))
        self._broadcast_storage_trigger(kind="s3", action="changed")

    def _on_s3_credentials_gone(self, event: CredentialsGoneEvent) -> None:
        """Handler for s3 credentials gone event."""
        if self._resolver.get_storage_type() == "conflict":
            return

        keystore_entries = ["s3.client.default.access_key", "s3.client.default.secret_key"]
        if not self._cleanup(object_storage_type="s3", keystore_entries=keystore_entries):
            return

        if self.charm.snapshots_manager.is_custom_s3_ca_stored():
            self.charm.snapshots_manager.store_s3_ca(None)
            self.charm.request_opensearch_restart(reason="clean up the object storage CA")
        self._broadcast_storage_trigger(kind="s3", action="gone")

    def _on_azure_credentials_changed(self, event: StorageConnectionInfoChangedEvent) -> None:
        """Handler for azure credentials changed event."""
        object_storage_type = self._resolver.get_storage_type() or "azure"

        if object_storage_type == "conflict":
            self.charm.status.set(BlockedStatus("More than 1 object storage relation."))
            event.defer()
            return

        if (
            object_storage_type != "azure"
            or not self._resolver.get_storage_config("azure")
            or not self._resolver.get_storage_config("azure").azure.credentials
        ):
            logger.warning("No Azure object storage configuration.")
            return

        self.charm.keystore_manager.put_entries(
            {
                "azure.client.default.account": self._resolver.get_storage_config(
                    "azure"
                ).azure.credentials.storage_account,
                "azure.client.default.key": self._resolver.get_storage_config(
                    "azure"
                ).azure.credentials.secret_key,
            }
        )
        self.charm.keystore_manager.reload()
        self._ensure_repository(object_storage_type, self._resolver.get_storage_config("azure"))
        self._broadcast_storage_trigger(kind="azure", action="changed")

    def _on_azure_credentials_gone(self, event: StorageConnectionInfoGoneEvent) -> None:
        """Handler for azure credentials gone event."""
        if self._resolver.get_storage_type() == "conflict":
            return

        keystore_entries = ["azure.client.default.account", "azure.client.default.key"]
        if not self._cleanup(object_storage_type="azure", keystore_entries=keystore_entries):
            return
        self._broadcast_storage_trigger(kind="azure", action="gone")

    def _broadcast_storage_trigger(self, kind: str, action: str) -> None:
        payload = json.dumps({"kind": kind, "action": action, "seq": int(time.time())})
        for rel in self.charm.model.relations.get(PeerClusterOrchestratorRelationName, []):
            rel.data[self.charm.app]["storage_trigger"] = payload

    def _on_object_storage_changed_on_peers(  # noqa: C901
        self, event: _ObjectStorageChanged
    ) -> None:
        """Handler for object storage changed event for sub-clusters."""
        if event.kind == "s3":
            info = self._read_s3_from_peer()
            if not (info and info["access_key"] and info["secret_key"]):
                return

            self.charm.keystore_manager.put_entries(
                {
                    "s3.client.default.access_key": info["access_key"],
                    "s3.client.default.secret_key": info["secret_key"],
                }
            )
            self.charm.keystore_manager.reload()

            # Optional CA chain
            if info.get("tls_ca_chain"):
                self.charm.snapshots_manager.store_s3_ca(info["tls_ca_chain"])
                try:
                    if self.charm.snapshots_manager.should_restart_for_full_setup(
                        "s3", object_storage_config=None
                    ):
                        self.charm.request_opensearch_restart("apply new object storage CA")
                except OpenSearchHttpError:
                    pass
            else:
                if self.charm.snapshots_manager.is_custom_s3_ca_stored():
                    self.charm.snapshots_manager.store_s3_ca(None)

        elif event.kind == "azure":
            info = self._read_azure_from_peer()
            if not (info and info["storage_account"] and info["secret_key"]):
                return

            self.charm.keystore_manager.put_entries(
                {
                    "azure.client.default.account": info["storage_account"],
                    "azure.client.default.key": info["secret_key"],
                }
            )
            self.charm.keystore_manager.reload()

    def _on_object_storage_gone_on_peers(self, event: _ObjectStorageGone) -> None:
        if event.kind == "s3":
            if self._cleanup(
                "s3", ["s3.client.default.access_key", "s3.client.default.secret_key"]
            ):
                if self.charm.snapshots_manager.is_custom_s3_ca_stored():
                    self.charm.snapshots_manager.store_s3_ca(None)
                    self.charm.request_opensearch_restart("clean up the object storage CA")
        elif event.kind == "azure":
            self._cleanup("azure", ["azure.client.default.account", "azure.client.default.key"])

    def _maybe_emit_local_storage_event(self, trigger: dict) -> bool:
        seq = int(trigger.get("seq", 0))
        kind = trigger.get("kind")
        action = trigger.get("action")
        if kind not in {"s3", "azure"} or action not in {"changed", "gone"}:
            return False

        last_seq = int(self.charm.peers_data.get(Scope.APP, "snapshots_last_storage_seq", 0))
        if seq <= last_seq:  # stale/replayed
            return False

        # watermark first to avoid double work on retries
        self.charm.peers_data.put(Scope.APP, "snapshots_last_storage_seq", seq)

        if action == "changed":
            self.object_storage_changed.emit(kind=kind, action=action)
        else:
            self.object_storage_gone.emit(kind=kind, action=action)
        return True

    def _first_provider_rel_with_data(self):
        for rel in self.charm.model.relations.get(PeerClusterRelationName, []):
            appbag = rel.data.get(rel.app, {})
            if appbag.get("data"):
                return rel
        return None

    def _provider_rel_payload(self) -> dict | None:
        rel = self._first_provider_rel_with_data()
        if not rel:
            return None
        try:
            return json.loads(rel.data[rel.app]["data"])
        except Exception:
            return None

    def _secret_value_from_id(self, secret_uri: str) -> str | None:
        try:
            s: Secret = self.charm.model.get_secret(id=secret_uri)
            content = s.get_content(refresh=True)
            return next(iter(content.values())) if content else None
        except Exception:
            return None

    def _read_s3_from_peer(self):
        payload = self._provider_rel_payload()
        if not payload:
            return None
        creds = (payload.get("credentials") or {}).get("s3") or {}
        if not creds:
            return None
        ak_id = creds.get("access-key")
        sk_id = creds.get("secret-key")
        if not (ak_id and sk_id):
            return None

        access_key = self._secret_value_from_id(ak_id)
        secret_key = self._secret_value_from_id(sk_id)

        # CA chain may be published separately
        tls_chain = None
        s3_ca = (payload.get("credentials") or {}).get("s3_tls_ca_chain")
        if isinstance(s3_ca, str) and s3_ca.startswith("secret://"):
            tls_chain = self._secret_value_from_id(s3_ca)

        return {"access_key": access_key, "secret_key": secret_key, "tls_ca_chain": tls_chain}

    def _read_azure_from_peer(self):
        payload = self._provider_rel_payload()
        if not payload:
            return None
        creds = (payload.get("credentials") or {}).get("azure") or {}
        if not creds:
            return None
        sa_id = creds.get("storage-account")
        sk_id = creds.get("secret-key")
        if not (sa_id and sk_id):
            return None

        storage_account = self._secret_value_from_id(sa_id)
        secret_key = self._secret_value_from_id(sk_id)
        return {"storage_account": storage_account, "secret_key": secret_key}

    def get_active_storage_type(self) -> Optional[ObjectStorageType]:
        """Get the active storage type."""
        return self._resolver.get_storage_type()

    def get_object_storage_config(
        self, forced_type: ObjectStorageType | None = None
    ) -> Optional[ObjectStorageConfig]:
        """Get the object storage config."""
        return self._resolver.get_storage_config(forced_type)

    def get_s3_info(self) -> Optional[S3RelData]:
        """Get the s3 info."""
        cfg = (
            self.get_object_storage_config("s3")
            if self.get_active_storage_type() in {"s3", "s3-pcluster"}
            else self.get_object_storage_config()
        )
        return cfg.s3 if cfg and cfg.s3 else None

    def get_azure_info(self) -> Optional[AzureRelData]:
        """Get the azure info."""
        cfg = (
            self.get_object_storage_config("azure")
            if self.get_active_storage_type() in {"azure", "azure-pcluster"}
            else self.get_object_storage_config()
        )
        return cfg.azure if cfg and cfg.azure else None

    def get_gcs_info(self) -> Optional[GcsRelData]:
        """Get the gcs info."""
        cfg = (
            self.get_object_storage_config("gcs")
            if self.get_active_storage_type() in {"gcs", "gcs-pcluster"}
            else self.get_object_storage_config()
        )
        return cfg.gcs if cfg and cfg.gcs else None

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handler for s3 create backup action event."""
        if error_message := self._action_missing_pre_requisites():
            event.fail(error_message)
            return

        object_storage_type = self._effective_type()
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
        self.charm.status.set(MaintenanceStatus(BackupInProgress))
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
            object_storage_type = self._effective_type()
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

    def _snapshot_index_names(self, snapshot: Any) -> List[str]:
        """Return list of index names from various snapshot shapes.

        Accepts dicts ({"indices": [...]}) or objects with .indices (list[str]/list[dict]).
        """
        # get raw indices container
        if isinstance(snapshot, dict):
            raw = snapshot.get("indices") or snapshot.get("index_names") or []
        else:
            raw = getattr(snapshot, "indices", [])

        # normalize to list[str]
        names: List[str] = []
        if isinstance(raw, list):
            for it in raw:
                if isinstance(it, str):
                    names.append(it)
                elif isinstance(it, dict):
                    names.append(it.get("index") or it.get("name"))
        elif isinstance(raw, dict):
            for k, v in raw.items():
                if isinstance(v, dict) and ("index" in v or "name" in v):
                    names.append(v.get("index") or v.get("name"))
                else:
                    names.append(k)

        return [n for n in names if n]

    def _indices_to_restore(self, snapshot: Any) -> list[str]:
        """Indices we will actually restore (skipping known noisy/system ones)."""
        names = self._snapshot_index_names(snapshot)
        return [n for n in names if n not in SKIP_ON_RESTORE]

    def _on_restore_action(self, event: ActionEvent) -> None:  # noqa C901
        """Handler for the restore action."""
        snapshot_id = event.params.get("backup-id")
        if error_message := self._action_missing_pre_requisites():
            event.fail(error_message)
            return

        object_storage_type = self._effective_type()

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
            to_restore = self._indices_to_restore(snapshot)
            closed_indices, indices_failed_to_close = (
                self.charm.snapshots_manager.close_snapshot_indices_open_in_cluster(
                    snapshot, only_indices=to_restore
                )
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
                object_storage_type=object_storage_type,
                snapshot=snapshot,
                only_indices=to_restore,
                include_global_state=False,
                ignore_unavailable=True,
                partial=True,
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

        if dep.typ == DeploymentType.MAIN_ORCHESTRATOR:
            return

        trigger_raw = event.relation.data.get(event.app, {}).get("storage_trigger")
        if trigger_raw:
            try:
                trigger = json.loads(trigger_raw)
            except json.JSONDecodeError:
                trigger = None

            if trigger and self._maybe_emit_local_storage_event(trigger):
                pass

    def _on_peer_clusters_relation_departed_for_snapshots(self, event):  # noqa C901
        """Cleanup snapshot config if the orchestrator we depended on is gone."""
        if not self.charm.unit.is_leader():
            return

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            return

        if dep.typ == DeploymentType.MAIN_ORCHESTRATOR:
            return

        trigger_raw = event.relation.data.get(event.app, {}).get("storage_trigger")
        if trigger_raw:
            try:
                trigger = json.loads(trigger_raw)
            except json.JSONDecodeError:
                trigger = None

            if trigger and self._maybe_emit_local_storage_event(trigger):
                pass

    def _cleanup(self, object_storage_type, keystore_entries):
        """Cleanup object storage config with 3 retries using tenacity."""
        if not object_storage_type:
            return True

        if keystore_entries:
            try:
                self.charm.keystore_manager.remove_entries(keystore_entries)
                self.charm.keystore_manager.reload()
                logger.info("Removed keystore entries for %s", object_storage_type)
            except OpenSearchCmdError as e:
                msg = f"{getattr(e, 'stdout', '')}{getattr(e, 'stderr', '')}"
                if "does not exist" in msg:
                    logger.info("Keystore entries already absent for %s.", object_storage_type)
                else:
                    logger.warning("Keystore cleanup error for %s: %s", object_storage_type, e)

        try:
            self._remove_repo_with_retry(object_storage_type)
            return True
        except Exception as e:
            logger.error("Repo cleanup for %s failed after 3 attempts: %s", object_storage_type, e)
            return False

    @retry(stop=stop_after_attempt(2), wait=wait_fixed(2), reraise=True)
    def _remove_repo_with_retry(self, object_storage_type):
        """Try to remove snapshot repo up to 2 times."""
        try:
            status = self.charm.health.get(wait_for_green_first=False)
            if status not in {HealthColors.YELLOW, HealthColors.GREEN}:
                raise RuntimeError(f"Cluster health is {status}")
            self.charm.snapshots_manager.remove_repo(object_storage_type=object_storage_type)
            logger.info("Removed repo for %s", object_storage_type)
        except OpenSearchHttpError as e:
            body = e.response_body or ""
            if "repository_missing_exception" in str(body):
                logger.info("Repo for %s already absent", object_storage_type)
                return
            raise

    def _peer_storage_kind(self) -> str | None:
        payload = self._provider_rel_payload() or {}
        creds = payload.get("credentials") or {}
        if "s3" in creds and creds["s3"]:
            return "s3-pcluster"
        if "azure" in creds and creds["azure"]:
            return "azure-pcluster"
        if "gcs" in creds and creds["gcs"]:
            return "gcs-pcluster"
        return None

    def _effective_type(self, forced_kind: str | None = None) -> str | None:
        """Decide the storage type in this unit’s context."""
        if forced_kind in {"s3", "azure", "gcs"}:
            return forced_kind + "-pcluster"
        typ = self._resolver.get_storage_type()
        return typ or self._peer_storage_kind()

    def _effective_config(self, typ: str | None):
        """Return an ObjectStorageConfig if we’re the main (resolver knows all repo settings)."""
        if typ in {"s3", "azure", "gcs"}:
            return self._resolver.get_storage_config(typ)
        return None  # sub-cluster doesn’t try to create repo, just manage keystore/CA

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

        ost = self._effective_type()
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
                osc = self._effective_config(ost)
                if not osc:
                    return "Object storage configuration not ready."
                if ost == "s3-pcluster" or ost == "azure-pcluster":
                    return "Repository should be created by main orchestrator."
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
        if object_storage_type == "s3":
            settings = {
                "bucket": object_storage_config.s3.bucket,
                "base_path": object_storage_config.s3.base_path,
                "region": object_storage_config.s3.region,
                "endpoint": object_storage_config.s3.endpoint,
            }

        elif object_storage_type == "azure":
            settings = {
                "container": object_storage_config.azure.container,
                "base_path": object_storage_config.azure.base_path,
            }
        elif object_storage_type == "gcs":
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
        logger.info("indices_clause: %s", indices_clause)
        # create snapshot
        response = self.opensearch.request(
            "PUT",
            f"_snapshot/{repo_name}/{snapshot_id}?wait_for_completion=false",
            payload={"indices": indices_clause, "ignore_unavailable": True},
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
        self,
        object_storage_type: ObjectStorageType,
        snapshot,
        only_indices=None,
        include_global_state=False,
        ignore_unavailable=True,
        partial=True,
    ) -> set[str]:
        """Restore an OpenSearch snapshot."""
        repo_name = self.repository_name(object_storage_type)
        snapshot_id = snapshot.get("snapshot")
        ignore = [f"-{idx}" for idx in SYSTEM_INDICES]
        indices_clause = ",".join(["*"] + ignore)

        payload = {
            "indices": indices_clause,
            "include_global_state": include_global_state,
            "ignore_unavailable": ignore_unavailable,
            "partial": partial,
        }
        if only_indices:
            payload["indices"] = ",".join(only_indices)
        restore_resp = self.opensearch.request(
            "POST",
            f"_snapshot/{repo_name}/{snapshot_id}/_restore?wait_for_completion=true",
            payload=payload,
            alt_hosts=self.charm.alt_hosts,
        )
        logger.info("Restore of snapshot '%s' response: %s", snapshot_id, restore_resp)

        # this only serves as documentation and should always be true if no previous HTTP error
        if "accepted" in restore_resp:
            pass
        else:
            snap_field = restore_resp.get("snapshot")
            if isinstance(snap_field, dict):
                assert snap_field.get("snapshot") == snapshot_id
            elif isinstance(snap_field, str):
                assert snap_field == snapshot_id
            else:
                logger.warning("Unexpected restore response shape: %r", snap_field)

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
        self,
        snapshot: dict[str, Any],
        skip: Optional[Iterable[str]] = None,
    ) -> Tuple[list[str] | None, dict[str, Any] | None]:
        """Close the non-system indices included in a given snapshot.

        `skip` contains index names that must NOT be closed (e.g., ML/config indices).
        """
        all_open = self._get_snapshot_indices_open_in_cluster(snapshot)
        if not all_open:
            logger.info("No indices to close.")
            return None, None

        skip = set(skip or ())
        indices_to_close = [i for i in all_open if i not in skip]
        if not indices_to_close:
            logger.info("No indices to close after filtering (all were skipped).")
            return None, None

        logger.info("Attempting closing the indices: %s", indices_to_close)
        response = self.opensearch.request("POST", f"{','.join(indices_to_close)}/_close")

        if response.get("acknowledged") and response.get("shards_acknowledged"):
            logger.info("Successfully closed all indices: %s.", indices_to_close)
            return indices_to_close, None

        indices_failed_to_close = {
            index: payload
            for index, payload in (response.get("indices") or {}).items()
            if not payload.get("closed")
        }
        closed_indices = [i for i in indices_to_close if i not in indices_failed_to_close]

        if indices_failed_to_close:
            logger.error("Failed to close some indices: %s", indices_failed_to_close)
        return closed_indices, indices_failed_to_close

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def _get_snapshot_indices_open_in_cluster(self, snapshot: dict[str, Any]) -> list[str]:
        """Fetch the current open indices in the current cluster."""
        current_indices = ClusterState.indices(self.opensearch)

        def _is_open(meta: dict) -> bool:
            return meta.get("status", "") == "open"

        return sorted(
            [
                idx
                for idx in snapshot.get("indices", [])
                if idx in current_indices
                and idx not in SYSTEM_INDICES
                and _is_open(current_indices[idx])
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
        chain = (object_storage_config.s3 and object_storage_config.s3.tls_ca_chain) or None
        if not chain:
            return False

        logger.info("S3 CA is required.")
        return True

    def is_custom_s3_ca_stored(self, s3_ca_chain: str | None = None) -> bool:
        """Check if a custom CA for the object storage is stored in the cacerts trust store."""
        stored_cacerts = (
            list_cas(store_pwd="changeit", store_path=f"{self.opensearch.paths.certs}/cacerts.p12")
            or {}
        )
        if not s3_ca_chain:
            return stored_cacerts.get("s3-snapshots-gateway") is not None

        return stored_cacerts.get("s3-snapshots-gateway") == s3_ca_chain

    def store_s3_ca(self, s3_tls_ca_chain: str | None) -> None:
        """Store or remove an S3 TLS CA chain on the cacerts trust store."""
        if s3_tls_ca_chain:
            store_s3_ca(
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
