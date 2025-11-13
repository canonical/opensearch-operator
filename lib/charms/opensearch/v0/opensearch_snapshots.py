# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Snapshots."""

import json
import logging
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Tuple

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
    OPENSEARCH_BACKUP_ID_FORMAT,
    S3_RELATION,
    BackupCredentialCAIncorrect,
    BackupCredentialKeysIncorrect,
    BackupInProgress,
    BackupRelConflict,
    BackupRelDataIncomplete,
    BackupRelShouldNotExist,
    PeerClusterOrchestratorRelationName,
    PeerClusterRelationName,
    RestoreInProgress,
)
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.helper_security import (
    _hash,
    _normalize_chain,
    list_cas,
    remove_ca,
    store_s3_ca,
)
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
    Relation,
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
S3_CA_ALIAS = "s3-snapshots-gateway"

# System indices that should not be snapshotted/restored
SYSTEM_INDICES = {
    ".opendistro_security",
    ".opensearch-sap-log-types-config",
    OpenSearchNodeLock.OPENSEARCH_INDEX,
}

CA_ERRORS = (
    "certificate verify failed",
    "pkix path",
    "valid certification path",
    "self signed certificate",
    "sslhandshakeexception",
    "validator_exception",
    "unable to find valid",
)

_CONFLICT_FLAG = {
    "s3": "snapshots_publish_after_conflict_s3",
    "azure": "snapshots_publish_after_conflict_azure",
}


class _ObjectStorageEvent(EventBase):
    def __init__(self, handle, *, kind: str, action: str):
        super().__init__(handle)
        self.kind = kind
        self.action = action

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

    @property
    def resolver(self) -> ObjectStorageResolver:
        """Resolve object storage."""
        return self._resolver

    def _on_s3_credentials_changed(self, event: CredentialsChangedEvent) -> None:  # noqa: C901
        """Handler for s3 credentials changed event."""
        dep = self.charm.opensearch_peer_cm.deployment_desc()
        # block non-main orchestrators only when they are in a multi-app topology.
        if dep and dep.typ != DeploymentType.MAIN_ORCHESTRATOR and self._has_peer_topology():
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupRelShouldNotExist), app=True)
            return

        object_storage_type = self.resolver.get_storage_type() or "s3"
        logger.info(f"S3 credentials changed for object storage type {object_storage_type}")
        if object_storage_type == "conflict":
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupRelConflict), app=True)
            event.defer()
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelConflict, app=True)

        cfg = self.resolver.get_storage_config("s3")
        creds = getattr(getattr(cfg, "s3", None), "credentials", None)
        # handle case where this was deferred in the above case, then the s3 relation was severed
        if object_storage_type != "s3" or not cfg or not creds:
            logger.warning("No S3 object storage configuration.")
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupRelDataIncomplete), app=True)
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelDataIncomplete, app=True)

        # apply locally (leader does cluster-level config)
        self.charm.keystore_manager.put_entries(
            {
                "s3.client.default.access_key": self.resolver.get_storage_config(
                    "s3"
                ).s3.credentials.access_key,
                "s3.client.default.secret_key": self.resolver.get_storage_config(
                    "s3"
                ).s3.credentials.secret_key,
            }
        )
        logger.info("S3 credentials are added to keystore.")
        self.charm.keystore_manager.reload()

        need_custom_ca = self.charm.snapshots_manager.requires_custom_s3_ca(
            object_storage_type, cfg
        )
        new_chain = cfg.s3.tls_ca_chain if need_custom_ca else None

        if new_chain:
            self.charm.snapshots_manager.store_s3_ca(new_chain)
            logger.info("S3 CA stored.")
        else:
            if self.charm.snapshots_manager.is_custom_s3_ca_stored():
                self.charm.snapshots_manager.store_s3_ca(None)
                logger.info("S3 CA removed.")

        self._restart_for_ca(new_chain, reason="apply object storage CA change")

        try:
            self._ensure_repository(object_storage_type, cfg)
            self.charm.snapshots_manager.verify_repository("s3")
        except OpenSearchHttpError as e:
            if self.charm.unit.is_leader():
                self._set_app_to_blocked(self.classify_os_repo_errors(e))
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupCredentialKeysIncorrect, app=True)
            self.charm.status.clear(BackupCredentialCAIncorrect, app=True)

        self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
        self._broadcast_storage_trigger(kind="s3", action="changed")

    def _on_s3_credentials_gone(self, event: CredentialsGoneEvent) -> None:
        """Handler for s3 credentials gone event."""
        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelShouldNotExist, app=True)

        if self.resolver.get_storage_type() == "conflict":
            return

        keystore_entries = ["s3.client.default.access_key", "s3.client.default.secret_key"]
        if not self._cleanup(
            object_storage_type="s3", keystore_entries=keystore_entries, remove_repo=True
        ):
            logger.warning("Cleanup for s3 credentials are failed.")
            return

        if self.charm.snapshots_manager.is_custom_s3_ca_stored():
            self.charm.snapshots_manager.store_s3_ca(None)
            self._restart_for_ca(None, reason="clean up the object storage CA")

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupCredentialKeysIncorrect, app=True)
            self.charm.status.clear(BackupCredentialCAIncorrect, app=True)

        self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
        self._broadcast_storage_trigger(kind="s3", action="gone")

    def _on_azure_credentials_changed(  # noqa: C901
        self, event: StorageConnectionInfoChangedEvent
    ) -> None:
        """Handler for azure credentials changed event."""
        dep = self.charm.opensearch_peer_cm.deployment_desc()
        # block non-main orchestrators only when they are in a multi-app topology.
        if dep and dep.typ != DeploymentType.MAIN_ORCHESTRATOR and self._has_peer_topology():
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupRelShouldNotExist), app=True)
            return

        object_storage_type = self.resolver.get_storage_type() or "azure"

        if object_storage_type == "conflict":
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupRelConflict), app=True)
            event.defer()
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelConflict, app=True)

        cfg = self.resolver.get_storage_config("azure")
        creds = getattr(getattr(cfg, "azure", None), "credentials", None)

        if object_storage_type != "azure" or not cfg or not creds:
            logger.warning("No Azure object storage configuration.")
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupRelDataIncomplete), app=True)
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelDataIncomplete, app=True)

        self.charm.keystore_manager.put_entries(
            {
                "azure.client.default.account": self.resolver.get_storage_config(
                    "azure"
                ).azure.credentials.storage_account,
                "azure.client.default.key": self.resolver.get_storage_config(
                    "azure"
                ).azure.credentials.secret_key,
            }
        )
        self.charm.keystore_manager.reload()
        try:
            self._ensure_repository(object_storage_type, cfg)
            self.charm.snapshots_manager.verify_repository("azure")
        except OpenSearchHttpError:
            if self.charm.unit.is_leader():
                self.charm.status.set(
                    BlockedStatus(BackupCredentialKeysIncorrect),
                    app=True,
                )
            return
        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupCredentialKeysIncorrect, app=True)

        self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
        self._broadcast_storage_trigger(kind="azure", action="changed")

    def _on_azure_credentials_gone(self, event: StorageConnectionInfoGoneEvent) -> None:
        """Handler for azure credentials gone event."""
        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelShouldNotExist, app=True)

        if self.resolver.get_storage_type() == "conflict":
            return

        keystore_entries = ["azure.client.default.account", "azure.client.default.key"]
        if not self._cleanup(
            object_storage_type="azure", keystore_entries=keystore_entries, remove_repo=True
        ):
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupCredentialKeysIncorrect, app=True)

        self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)
        self._broadcast_storage_trigger(kind="azure", action="gone")

    @staticmethod
    def classify_os_repo_errors(err: "OpenSearchHttpError") -> str:
        """Detect the CA or key related errors."""
        text = json.dumps(
            getattr(err, "response_body", {}), ensure_ascii=False, default=str
        ).lower()
        if "imds" in text or "failed to load credentials" in text:
            return "KEYS"
        return "CA" if any(f in text for f in CA_ERRORS) else "KEYS"

    def _set_app_to_blocked(self, kind: str) -> None:
        """Set one of two Blocked statuses on the app."""
        if kind == "CA":
            self.charm.status.set(BlockedStatus(BackupCredentialCAIncorrect), app=True)
        else:
            self.charm.status.set(BlockedStatus(BackupCredentialKeysIncorrect), app=True)

    def _broadcast_storage_trigger(self, kind: str, action: str) -> None:
        """Broadcast a storage change/gone trigger to peer orchestrators.

        Args:
            kind (str): kind of storage type
            action (str): action (change/gone.

        Only the leader may write to the application databag.
        """
        if not self.charm.unit.is_leader():
            logger.debug("Skipping storage trigger broadcast: not leader")
            return
        payload = json.dumps({"kind": kind, "action": action, "seq": int(time.time())})
        # Orchestrator relations
        for rel in self.charm.model.relations.get(PeerClusterOrchestratorRelationName, []):
            try:
                rel.data[self.charm.app]["storage_trigger"] = payload
            except Exception as e:
                logger.warning(
                    "Failed to write storage_trigger to orchestrator rel %s: %s", rel.id, e
                )

        # Provider relations (subclusters consume this)
        for rel in self.charm.model.relations.get(PeerClusterRelationName, []):
            try:
                rel.data[self.charm.app]["storage_trigger"] = payload
            except Exception as e:
                logger.warning("Failed to write storage_trigger to provider rel %s: %s", rel.id, e)

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
            if info.get("s3_tls_ca_chain"):
                logger.info("S3 TLS CA Chain detected.")
                self.charm.snapshots_manager.store_s3_ca(info["s3_tls_ca_chain"])
                self._restart_for_ca(info["s3_tls_ca_chain"], reason="apply new object storage CA")

            else:
                if self.charm.snapshots_manager.is_custom_s3_ca_stored():
                    self.charm.snapshots_manager.store_s3_ca(None)
                    self._restart_for_ca(None, reason="clean up the object storage CA")

        elif event.kind == "azure":
            info = self._read_azure_from_peer()
            if not (info and info["storage_account"] and info["secret_key"]):
                logger.warning("No Azure storage configuration.")
                return

            self.charm.keystore_manager.put_entries(
                {
                    "azure.client.default.account": info["storage_account"],
                    "azure.client.default.key": info["secret_key"],
                }
            )
            logger.info("Azure storage credentials are added to keystore.")
            self.charm.keystore_manager.reload()

    def _on_object_storage_gone_on_peers(self, event: _ObjectStorageGone) -> None:
        if event.kind == "s3":
            if self._cleanup(
                "s3",
                ["s3.client.default.access_key", "s3.client.default.secret_key"],
            ):
                if self.charm.snapshots_manager.is_custom_s3_ca_stored():
                    self.charm.snapshots_manager.store_s3_ca(None)
                    self._restart_for_ca(None, reason="clean up the object storage CA")
        elif event.kind == "azure":
            self._cleanup("azure", ["azure.client.default.account", "azure.client.default.key"])

    def _current_s3_ca_chain(self) -> str:
        """Return the currently stored S3 CA chain (string) from cacerts, or ''."""
        try:
            stored = (
                list_cas(
                    store_pwd="changeit",
                    store_path=f"{self.charm.opensearch.paths.certs}/cacerts.p12",
                )
                or {}
            )
            return stored.get(S3_CA_ALIAS) or ""
        except Exception:
            return ""

    def _ca_changed(self, new_chain: str | None) -> bool:
        current_norm = _normalize_chain(self._current_s3_ca_chain())
        new_norm = _normalize_chain(new_chain)
        return _hash(current_norm) != _hash(new_norm)

    def _restart_for_ca(self, new_chain: str | None, *, reason: str) -> bool:
        """Request restart iff the installed CA differs from new_chain.

        Returns:
             True if we requested a restart, else False.
        """
        if self._ca_changed(new_chain):
            self.charm.request_opensearch_restart(reason=reason)
            return True
        return False

    def _get_peer_orchestrator_relation_payload(self, relation) -> str | None:
        app_bag = {}
        if relation is not None:
            app_bag = relation.data.get(relation.app, {}) or {}
        else:
            rel = self._find_provider_relation_with_data()
            if rel:
                app_bag = rel.data.get(rel.app, {}) or {}

        return app_bag.get("data")

    def _emit_local_storage_event(self, trigger: dict, relation=None) -> bool:  # noqa: C901
        """Emit local storage event only when payload is ready in this relation.

        Args:
            trigger: a dict written taken from peer relation data used
                    to judge to emit a custom event or not
            relation: an optional relation object used to judge to emit a custom event

        Returns:
             True if we emitted (and watermarked), False otherwise.

        Trigger provides 3 keys: action, kind and seq keys
        Action can be changed or gone meaning relation changed or gone.
        Kind is the relation type: S3 or Azure.
        Seq key is the timestamp when this information is set.
        """
        seq = int(trigger.get("seq", 0))
        kind = trigger.get("kind")
        action = trigger.get("action")
        if kind not in {"s3", "azure"} or action not in {"changed", "gone"}:
            return False

        payload_raw = self._get_peer_orchestrator_relation_payload(relation)

        if action == "changed":
            if not payload_raw:
                return False

            try:
                payload = json.loads(payload_raw)
            except Exception:
                return False

            creds = payload.get("credentials") or {}
            if kind == "s3":
                if not isinstance(creds.get("s3"), dict):
                    return False
            elif kind == "azure":
                if not isinstance(creds.get("azure"), dict):
                    return False

        scope = Scope.APP if self.charm.unit.is_leader() else Scope.UNIT

        # Use watermarks to avoid cross-kind masking
        key = "snapshots_last_storage_seq"
        last_seq = int(self.charm.peers_data.get(scope, key, 0))
        if seq <= last_seq:
            return False

        self.charm.peers_data.put(scope, key, seq)

        if action == "changed":
            self.object_storage_changed.emit(kind=kind, action=action)
        elif action == "gone":
            self.object_storage_gone.emit(kind=kind, action=action)
            # After conflicts are resolved, we should check which credentials
            # are really exist in the Peer Cluster Orchestrator relation data
            try:
                payload = json.loads(payload_raw)
                if payload and payload.get("credentials"):
                    creds = payload.get("credentials")
                    if creds.get("s3"):
                        self.object_storage_changed.emit(kind="s3", action="changed")
                    elif creds.get("azure"):
                        self.object_storage_changed.emit(kind="azure", action="changed")
            except Exception:
                logger.warning("Payload is not valid JSON")

        return True

    def _find_provider_relation_with_data(self) -> Relation | None:
        """Return the first PeerCluster provider relation that already carries data.

        Looks through all active peer-cluster provider relations and returns the first
        relation whose remote app databag contains the key data. If none are
        found, returns None.

        Returns:
            Relation: The relation whose remote app databag has data,
             else None if no such relation exists.
        """
        for rel in self.charm.model.relations.get(PeerClusterRelationName, []):
            app_bag = rel.data.get(rel.app, {})
            if app_bag.get("data"):
                return rel
        return None

    def _get_provider_rel_payload(self) -> dict | None:
        rel = self._find_provider_relation_with_data()
        if not rel:
            logger.info("no rel payload found")
            return
        try:
            payload = json.loads(rel.data[rel.app]["data"])
            logger.info("provided payload: %s", payload)
            return payload
        except Exception:
            logger.warning("failed to load provided payload")
            return

    def _secret_value_from_id(self, secret_uri: str) -> str | None:
        try:
            s: Secret = self.charm.model.get_secret(id=secret_uri)
            content = s.get_content(refresh=True)
            return next(iter(content.values())) if content else None
        except Exception:
            return

    def _read_s3_from_peer(self) -> dict[str, str] | None:
        payload = self._get_provider_rel_payload()
        if not payload:
            return
        creds = (payload.get("credentials") or {}).get("s3") or {}
        if not creds:
            return
        access_key_secret_id = creds.get("access-key")
        secret_key_secret_id = creds.get("secret-key")
        if not (access_key_secret_id and secret_key_secret_id):
            return

        access_key = self._secret_value_from_id(access_key_secret_id)
        secret_key = self._secret_value_from_id(secret_key_secret_id)

        # CA chain may be published separately
        tls_chain = None
        s3_ca_secret_id = (payload.get("credentials") or {}).get("s3_tls_ca_chain")
        logger.info("S3 CA secret ID: %s", s3_ca_secret_id)
        if isinstance(s3_ca_secret_id, str) and s3_ca_secret_id.startswith("secret://"):
            tls_chain = self._secret_value_from_id(s3_ca_secret_id)

        return {"access_key": access_key, "secret_key": secret_key, "s3_tls_ca_chain": tls_chain}

    def _read_azure_from_peer(self) -> dict[str, str] | None:
        payload = self._get_provider_rel_payload()
        if not payload:
            return
        creds = (payload.get("credentials") or {}).get("azure") or {}
        if not creds:
            logger.warning("no Azure credentials found.")
            return
        storage_account_secret_id = creds.get("storage-account")
        secret_key_secret_id = creds.get("secret-key")
        if not (storage_account_secret_id and secret_key_secret_id):
            logger.debug("Azure storage credentials are incomplete.")
            return

        storage_account = self._secret_value_from_id(storage_account_secret_id)
        secret_key = self._secret_value_from_id(secret_key_secret_id)
        return {"storage_account": storage_account, "secret_key": secret_key}

    def get_active_storage_type(self) -> ObjectStorageType | None:
        """Get the active storage type."""
        return self.resolver.get_storage_type()

    def get_object_storage_config(
        self, forced_type: ObjectStorageType | None = None
    ) -> ObjectStorageConfig | None:
        """Get the object storage config."""
        return self.resolver.get_storage_config(forced_type)

    def get_s3_info(self) -> Optional[S3RelData]:
        """Get the s3 info."""
        cfg = (
            self.get_object_storage_config("s3")
            if self.get_active_storage_type() in {"s3", "s3-pcluster"}
            else self.get_object_storage_config()
        )
        return cfg.s3 if cfg and cfg.s3 else None

    def get_azure_info(self) -> AzureRelData | None:
        """Get the azure info."""
        cfg = (
            self.get_object_storage_config("azure")
            if self.get_active_storage_type() in {"azure", "azure-pcluster"}
            else self.get_object_storage_config()
        )
        return cfg.azure if cfg and cfg.azure else None

    def get_gcs_info(self) -> GcsRelData | None:
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

    def _on_peer_clusters_relation_changed_for_snapshots(self, event) -> None:  # noqa C901
        """Apply snapshots config when the orchestrator broadcasts over peer-clusters."""
        # Only leaders perform cluster-level config
        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            event.defer()
            return

        if dep.typ == DeploymentType.MAIN_ORCHESTRATOR:
            return

        trigger_from_rel_data = event.relation.data.get(event.app, {}).get("storage_trigger")
        if trigger_from_rel_data:
            try:
                trigger_data = json.loads(trigger_from_rel_data)
            except json.JSONDecodeError:
                trigger_data = None

            if not trigger_data:
                return

            # If emit returns False, payload not ready yet, defer
            if not self._emit_local_storage_event(trigger_data, relation=event.relation):
                event.defer()
                return

    def _on_peer_clusters_relation_departed_for_snapshots(self, event) -> None:  # noqa C901
        """Cleanup snapshot config if the orchestrator we depended on is gone."""
        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            return

        if dep.typ == DeploymentType.MAIN_ORCHESTRATOR:
            return

        trigger_raw_data = event.relation.data.get(event.app, {}).get("storage_trigger")
        if trigger_raw_data:
            try:
                trigger_data = json.loads(trigger_raw_data)
            except json.JSONDecodeError:
                trigger_data = None

            if not trigger_data:
                return

            # If emit returns False, payload not ready yet, defer
            if not self._emit_local_storage_event(trigger_data, relation=event.relation):
                event.defer()
                return

    def _cleanup(self, object_storage_type, keystore_entries, remove_repo=False) -> bool:
        """Cleanup object storage config.

        Args:
            object_storage_type (str): Object storage type
            keystore_entries (list): List of keystore entries
            remove_repo (bool, optional): Remove repo entries. Defaults to False.

        Returns:
            True if all the cleanup is successful, False otherwise
        """
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

        if remove_repo:
            try:
                self.charm.snapshots_manager.remove_repo(
                    object_storage_type=object_storage_type, require_healthy=True
                )
            except Exception as e:
                logger.error(
                    "Repo cleanup for %s failed after 3 attempts: %s", object_storage_type, e
                )
                return False
        return True

    def _peer_storage_kind(self) -> str | None:
        """Return the kind of storage type for peers."""
        payload = self._get_provider_rel_payload() or {}
        creds = payload.get("credentials") or {}
        if "s3" in creds and creds["s3"]:
            return "s3-pcluster"
        if "azure" in creds and creds["azure"]:
            return "azure-pcluster"
        if "gcs" in creds and creds["gcs"]:
            return "gcs-pcluster"
        return

    def _effective_type(self, forced_kind: str | None = None) -> str | None:
        """Decide the storage type in this unit’s context.

        Args:
            forced_kind (str | None): The kind of storage type to return.

        Returns:
            storage type if there is else None
        """
        if forced_kind in {"s3", "azure", "gcs"}:
            return forced_kind + "-pcluster"
        typ = self.resolver.get_storage_type()
        return typ or self._peer_storage_kind()

    def _effective_config(self, typ: str | None) -> ObjectStorageConfig | None:
        """Return an ObjectStorageConfig if we’re the main (resolver knows all repo settings).

        Args:
            typ (str | None): The kind of storage type to return.

        Returns:
            storage type if there is else None
        """
        if typ in {"s3", "azure", "gcs"}:
            return self.resolver.get_storage_config(typ)
        return

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

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            return "Deployment not ready."

        if self.charm.upgrade_in_progress:
            return "Backup/Restore operations not supported while upgrade in-progress."

        object_storage_type = self._effective_type()
        if not object_storage_type:
            return "Missing relation with an object storage integrator."

        if object_storage_type == "conflict":
            return "Conflict: more than one object storage integrators integrated."

        if not self.charm.opensearch.is_node_up() and not self.charm.alt_hosts:
            return "Connectivity issue: the opensearch service is not reachable."

        repo_name = self.charm.snapshots_manager.repository_name(object_storage_type)
        logger.debug(
            f"[snapshots] precheck: type={object_storage_type} repo={repo_name} alt_hosts={self.charm.alt_hosts}"
        )

        try:
            if not self.charm.snapshots_manager.is_repository_created(object_storage_type):
                object_storage_config = self._effective_config(object_storage_type)
                if not object_storage_config:
                    return "Object storage configuration not ready."
                if object_storage_type == "s3-pcluster" or object_storage_type == "azure-pcluster":
                    return "Repository should be created by main orchestrator."
                logger.info(f"[snapshots] repo {repo_name} missing; attempting create.")
                self.charm.snapshots_manager.create_repo(
                    object_storage_type, object_storage_config
                )
                if not self.charm.snapshots_manager.is_repository_created(object_storage_type):
                    return "The opensearch repository has not been created yet."
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
                self.charm.snapshots_manager.is_snapshot_running()
                or self.charm.snapshots_manager.is_restore_running()
            ):
                return "Backup / Restore operation in progress."
        except OpenSearchHttpError as e:
            return f"Action failed with: {str(e)}."

        return

    def _ensure_repository(
        self, storage_type: ObjectStorageType, storage_cfg: ObjectStorageConfig
    ) -> None:
        """Create the repository if we have a storage type/config and it doesn't exist yet.

        Args:
            storage_type (ObjectStorageType): Object storage type
            storage_cfg (ObjectStorageConfig): Object storage config

        Raises:
            OpenSearchHttpError: repository does not exist
        """
        if not storage_type or not storage_cfg or storage_type == "conflict":
            return

        if not self.charm.unit.is_leader():
            return

        if not self.charm.snapshots_manager.is_repository_created(storage_type):
            self.charm.snapshots_manager.create_repo(
                object_storage_type=storage_type,
                object_storage_config=storage_cfg,
            )
            logger.info("Created snapshot repository for %s", storage_type)

    def _has_peer_topology(self) -> bool:
        """Return True if this app participates in a multi-app topology (main/failover/data)."""
        return bool(
            self.charm.model.relations.get(PeerClusterOrchestratorRelationName, [])
        ) or bool(self.charm.model.relations.get(PeerClusterRelationName, []))


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
        """Create an opensearch repository for storing backups.

        Args:
            object_storage_type (ObjectStorageType): Object storage type
            object_storage_config (ObjectStorageConfig): Object storage config
            name (str, optional): Name of the repository. Defaults to None.

        Returns:
            str: Repository name
        """
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
    def remove_repo(
        self,
        object_storage_type: ObjectStorageType,
        name: str | None = None,
        *,
        require_healthy: bool = True,
    ) -> None:
        """Remove the snapshot repository with retries and optional health gating.

        Args:
            object_storage_type: Object storage type to use
            name: Name of the repository to remove
            require_healthy: Requires that cluster state is healthy.
                        by default requires YELLOW/GREEN; set require_healthy=False to skip.

        """
        if not self.charm.unit.is_leader():
            return
        repo_name = name or self.repository_name(object_storage_type)
        if require_healthy:
            status = self.charm.health.get(wait_for_green_first=False)
            if status not in {HealthColors.YELLOW, HealthColors.GREEN}:
                raise RuntimeError(f"Cluster health is {status}, will retry repo removal")

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
        current_indices = ClusterState.indices(self.opensearch)

        def _is_open(meta: dict) -> bool:
            return meta["status"] == "open"

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
    def is_snapshot_running(self) -> bool:
        """Check if a snapshot is running.

        Returns:
            True if snapshot is running else False
        """
        response = self.opensearch.request(
            "GET", "_snapshot/_status", alt_hosts=self.charm.alt_hosts
        )
        return len(response.get("snapshots", [])) > 0

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def is_restore_running(self) -> bool:
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

    @staticmethod
    def requires_custom_s3_ca(
        object_storage_type: ObjectStorageType, object_storage_config: ObjectStorageConfig
    ) -> bool:
        """Check if the current object storage setup requires the use of a custom CA.

        Args:
            object_storage_type: Object storage type
            object_storage_config: Object storage config

        Returns:
            True if the current object storage setup requires the use of a custom CA, else False
        """
        if object_storage_type not in {"s3", "s3-pcluster"}:
            return False
        chain = (object_storage_config.s3 and object_storage_config.s3.tls_ca_chain) or None
        if not chain:
            return False

        logger.info("S3 CA is required.")
        return True

    def _find_s3_chain_in_store(self) -> str:
        """Return the currently stored S3 CA chain from cacerts, or ''.

        Returns:
            Stored CA chain if found, else ''.
        """
        stored_cacerts = (
            list_cas(
                store_pwd="changeit",
                store_path=f"{self.opensearch.paths.certs}/cacerts.p12",
            )
            or {}
        )
        if not stored_cacerts:
            return ""

        # list_cas returns aliases such as "s3-snapshots-gateway-0", "s3-snapshots-gateway-1"
        for alias, chain in stored_cacerts.items():
            if alias == S3_CA_ALIAS or alias.startswith(f"{S3_CA_ALIAS}-"):
                return chain or ""
        return ""

    def is_custom_s3_ca_stored(self, s3_ca_chain: str | None = None) -> bool:
        """Check if a custom CA for the object storage is stored in the cacerts trust store.

        Args:
            s3_ca_chain: CA chain which will be detected in the stored cacerts

        Returns:
            True if the given CA chain is stored in the stored cacerts, else False
        """
        current_chain = self._find_s3_chain_in_store()
        if not current_chain:
            # nothing stored
            return False

        if not s3_ca_chain:
            return True

        # Normalize both sides in case of whitespace/ordering differences
        return _normalize_chain(current_chain) == _normalize_chain(s3_ca_chain)

    def store_s3_ca(self, s3_tls_ca_chain: str | None) -> None:
        """Store or remove an S3 TLS CA chain on the cacerts trust store.

        Args:
            s3_tls_ca_chain: S3 TLS CA chain to store or remove

        If the there is s3_tls_ca_chain, the old CA will be removed.
        """
        store_path = f"{self.opensearch.paths.certs}/cacerts.p12"
        # Drop the CA entirely
        if not s3_tls_ca_chain:
            remove_ca(
                alias=S3_CA_ALIAS,
                store_pwd="changeit",
                store_path=store_path,
            )
            return

        # If we already have the same CA, skip re-import
        current_chain = self._find_s3_chain_in_store()
        if current_chain and _normalize_chain(current_chain) == _normalize_chain(s3_tls_ca_chain):
            logger.info("S3 CA unchanged; skipping re-import.")
            return

        # Chain changed: ensure we remove the old alias family first
        # to avoid keytool already exists error
        remove_ca(
            alias=S3_CA_ALIAS,
            store_pwd="changeit",
            store_path=store_path,
        )

        # Import fresh CA
        store_s3_ca(
            store_pwd="changeit",
            store_path=store_path,
            alias=S3_CA_ALIAS,
            ca=s3_tls_ca_chain,
            keep_previous=False,
        )

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
    def verify_repository(self, object_storage_type: ObjectStorageType) -> None:
        """Verify repo by listing snapshots.

        Args:
            object_storage_type (ObjectStorageType): Object storage type

        Raises:
            OpenSearchHttpError if there are any backend issues such as auth/perm errors
        """
        repo = self.repository_name(object_storage_type)
        # If creds/endpoint/perm are wrong, this call raises OpenSearchHttpError with a 500.
        _ = self.opensearch.request(
            "GET", f"_snapshot/{repo}/_all", alt_hosts=self.charm.alt_hosts, timeout=30
        )
