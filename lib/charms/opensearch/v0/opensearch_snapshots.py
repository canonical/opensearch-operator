# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Snapshots."""

import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Tuple

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
    PeerClusterRelationName,
    RestoreInProgress,
)
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.helper_plugins import (
    remove_plugin_secret,
    store_plugin_secret,
)
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
from charms.opensearch.v0.opensearch_internal_data import Scope
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
LIBPATCH = 2

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm


# Object storage types
ObjectStorageType = Literal[
    "s3", "azure", "gcs", "s3-pcluster", "azure-pcluster", "gcs-pcluster", "conflict"
]

# OpenSearch Repositories
S3_REPOSITORY = "s3-repository"
AZURE_REPOSITORY = "azure-repository"
GCS_REPOSITORY = "gcs-repository"

# System indices that should not be snapshotted
SYSTEM_INDICES = {
    ".opendistro_security",
    OpenSearchNodeLock.OPENSEARCH_INDEX,
}

# Plugin secret label used for cross-cluster distribution
SNAPSHOTS_SECRET_LABEL = "backup-credentials"


class OpenSearchSnapshotsEvents(Object):
    """Events class for Backups (snapshots)."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, key="backups")
        self.charm = charm

        # requirers
        self.s3_requirer = S3Requirer(charm, S3_RELATION)
        self.azure_requirer = AzureStorageRequires(charm, AZURE_RELATION)
        # simple deployments or main orchestrator
        self.framework.observe(
            self.s3_requirer.on.credentials_changed, self._on_s3_credentials_changed
        )
        self.framework.observe(charm.on.upgrade_charm, self._on_upgrade_charm_for_snapshots)
        self.framework.observe(charm.on.leader_elected, self._on_leader_elected_for_snapshots)
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

        # receive plugin secrets on sub-clusters
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

        # actions
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_action)

    # Provider side

    def _on_s3_credentials_changed(self, event: CredentialsChangedEvent) -> None:
        """Handler for s3 credentials changed event."""
        object_storage_type = self.object_storage_type or "s3"
        self.charm.peers_data.put(Scope.UNIT, "snapshot-object-storage-type", object_storage_type)

        if object_storage_type == "conflict":
            self.charm.status.set(BlockedStatus("More than 1 object storage relation"))
            event.defer()
            return

        if (
            object_storage_type != "s3"
            or not self.object_storage_config
            or not self.object_storage_config.s3
            or not self.object_storage_config.s3.credentials
        ):
            logger.warning("No S3 object storage configuration.")
            return

        # store CA if provided by integrator
        self.charm.snapshots_manager.store_s3_ca(self.object_storage_config.s3.tls_ca_chain)

        # add credentials to keystore
        s3 = self.object_storage_config.s3.credentials
        self.charm.keystore.add_entries(
            {
                "s3.client.default.access_key": s3.access_key,
                "s3.client.default.secret_key": s3.secret_key,
            }
        )
        if not self.charm.keystore.reload():
            event.defer()
            return

        # distribute to sub-clusters via plugin secret and remember secret_id
        self._publish_snapshots_secret("s3", self.object_storage_config)

        # If OpenSearch is running and the repo cannot be verified yet due to CA trust, request restart
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

        # remove local/unit tracking
        self.charm.plugin_manager.remove_plugin_config(
            scope=Scope.UNIT, label=SNAPSHOTS_SECRET_LABEL
        )
        self.charm.peers_data.delete(Scope.UNIT, "snapshot-object-storage-type")

        # provider cleans up APP-scoped secret + APP record
        if self.charm.unit.is_leader():
            remove_plugin_secret(self.charm, SNAPSHOTS_SECRET_LABEL)
            self.charm.plugin_manager.remove_plugin_config(
                scope=Scope.APP, label=SNAPSHOTS_SECRET_LABEL
            )

            # tell consumers the APP secret is gone so they drop unit keys
            if self.charm.opensearch_peer_cm.is_provider(typ="main"):
                self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)

        # if we had stored a custom CA for S3, remove it and restart to drop it
        if self.charm.snapshots_manager.is_custom_s3_ca_stored():
            self.charm.snapshots_manager.store_s3_ca(s3_tls_ca_chain=None)
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

        if object_storage_type != "azure" or not self.object_storage_config:
            return

        azure = self.object_storage_config.azure.credentials
        self.charm.keystore.add_entries(
            {
                "azure.client.default.account": azure.storage_account,
                "azure.client.default.key": azure.secret_key,
            }
        )
        if not self.charm.keystore.reload():
            event.defer()
            return

        # Ddstribute to sub-clusters via plugin secret and remember secret_id
        self._publish_snapshots_secret("azure", self.object_storage_config)

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

        # remove local/unit tracking
        self.charm.plugin_manager.remove_plugin_config(
            scope=Scope.UNIT, label=SNAPSHOTS_SECRET_LABEL
        )
        self.charm.peers_data.delete(Scope.UNIT, "snapshot-object-storage-type")

        # provider cleans up APP-scoped secret + APP record
        if self.charm.unit.is_leader():
            remove_plugin_secret(self.charm, SNAPSHOTS_SECRET_LABEL)
            self.charm.plugin_manager.remove_plugin_config(
                scope=Scope.APP, label=SNAPSHOTS_SECRET_LABEL
            )

            # notify consumers so they drop unit keys and repo
            if self.charm.opensearch_peer_cm.is_provider(typ="main"):
                self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)

    def _republish_if_possible(self, event=None) -> None:
        # only provider should publish
        if not (
            self.charm.unit.is_leader() and self.charm.opensearch_peer_cm.is_provider(typ="main")
        ):
            return

        typ = self.object_storage_type
        cfg = self.object_storage_config
        if typ in {"s3", "azure"} and cfg:
            logger.debug("[snapshots] republish_if_possible: typ=%s cfg=%s", typ, bool(cfg))
            self._publish_snapshots_secret(typ, cfg)

    def _on_upgrade_charm_for_snapshots(self, event):
        self._republish_if_possible(event)

    def _on_leader_elected_for_snapshots(self, event):
        self._republish_if_possible(event)

    # Secret reception on sub-clusters

    def _on_secret_changed(self, event) -> None:
        """Consume plugin-snapshots secret on sub-clusters and ensure repo."""
        # only leaders perform cluster-level config
        if not self.charm.unit.is_leader():
            return

        # accept provider labels, they look like <provider-app>:app:<label>
        if not event.secret.label.endswith(f":app:{SNAPSHOTS_SECRET_LABEL}"):
            return

        content = event.secret.get_content(refresh=True)
        cfg = self.parse_secret_content(content) or {}
        keys = cfg.get("keys", {})
        repo = cfg.get("repo", {})
        tls_ca_chain = cfg.get("tlscachain")

        # track keys on UNIT for cleanup
        self.charm.plugin_manager.put_plugin_config(
            scope=Scope.UNIT, label=SNAPSHOTS_SECRET_LABEL, cleanup={"keys": list(keys.keys())}
        )

        # apply keystore entries from secret
        if keys:
            self.charm.keystore.add_entries(keys)
            if not self.charm.keystore.reload():
                event.defer()
                return

        obj_type: ObjectStorageType | None = None
        osc: ObjectStorageConfig | None = None

        if repo.get("type") == "s3":
            # mark local storage type
            self.charm.peers_data.put(Scope.UNIT, "snapshot-object-storage-type", "s3-pcluster")

            # optionally store S3 CA
            if tls_ca_chain:
                self.charm.snapshots_manager.store_s3_ca(tls_ca_chain)

            # pull required/optional fields from keys.
            # If the key does not exist, use empty string not to get a Pydantic validation error
            ak = keys.get("s3.client.default.access_key") or ""
            sk = keys.get("s3.client.default.secret_key") or ""
            region = keys.get("s3.client.default.region") or ""
            endpoint = keys.get("s3.client.default.endpoint") or ""

            bucket = (repo.get("bucket") or "").strip()
            base_path = (repo.get("base_path") or "").strip()

            # build a valid ObjectStorageConfig for the consumer
            osc = ObjectStorageConfig(
                s3=S3RelData.from_dict(
                    {
                        "credentials": {
                            "access-key": ak,
                            "secret-key": sk,
                        },
                        "bucket": bucket,
                        "base-path": base_path,
                        "region": region,
                        "endpoint": endpoint,
                        "tls-ca-chain": tls_ca_chain,
                    }
                )
            )
            obj_type = "s3-pcluster"

        elif repo.get("type") == "azure":
            self.charm.peers_data.put(Scope.UNIT, "snapshot-object-storage-type", "azure-pcluster")
            container = (repo.get("container") or "").strip()
            base_path = (repo.get("base_path") or "").strip()
            osc = ObjectStorageConfig(
                azure=AzureRelData.from_dict(
                    {
                        "credentials": {},
                        "container": container,
                        "base-path": base_path,
                    }
                )
            )
            obj_type = "azure-pcluster"

        else:
            logger.warning("[plugins/peer] unsupported snapshot type: %s", repo.get("type"))
            return

        # ensure repo exists
        try:
            if not self.charm.snapshots_manager.is_repository_created(obj_type):
                self.charm.snapshots_manager.create_repo(obj_type, osc)
        except OpenSearchHttpError:
            event.defer()

    # Peer-cluster relation
    @staticmethod
    def parse_secret_content(content: dict) -> dict | None:
        """Accepts format: {"payload": "<json string>"}

        Args:
            content: secret content

        Returns:
             A dict like: {"keys": {...}, "repo": {...}, "tlscachain": "..."} or None.
        """
        s = content.get("payload")
        if isinstance(s, str):
            try:
                return json.loads(s)
            except Exception:
                return None
        return None

    def _on_peer_clusters_relation_changed_for_snapshots(self, event):
        """Apply snapshots config when the orchestrator broadcasts over peer-clusters.

        With plugin secrets, sub-clusters primarily react to secret_changed.
        """
        if not self.charm.unit.is_leader():
            return

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            event.defer()
            return
        if dep.typ == DeploymentType.MAIN_ORCHESTRATOR:
            return

        # If a type is already known locally, ensure repo exists
        object_storage_type = self.object_storage_type
        object_storage_config = self.object_storage_config
        if not object_storage_type or not object_storage_config:
            return
        if object_storage_type == "conflict":
            self.charm.status.set(BlockedStatus("More than 1 object storage relation."))
            event.defer()
            return

        if self.charm.snapshots_manager.should_restart_for_full_setup(
            object_storage_type=object_storage_type, object_storage_config=object_storage_config
        ):
            if self.charm.request_opensearch_restart(reason="apply new object storage CA"):
                event.defer()
                return

        self._ensure_repository()

    def _on_peer_clusters_relation_departed_for_snapshots(self, event):
        """Cleanup snapshot config if the orchestrator we depended on is gone."""
        if not self.charm.unit.is_leader():
            return

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            return

        object_storage_type = self.object_storage_type
        if not object_storage_type or object_storage_type == "conflict":
            return

        if object_storage_type == "s3-pcluster":
            keystore_entries = ["s3.client.default.access_key", "s3.client.default.secret_key"]
        elif object_storage_type == "azure-pcluster":
            keystore_entries = ["azure.client.default.account", "azure.client.default.key"]
        else:
            keystore_entries = []  # gcs

        if not self._cleanup(
            object_storage_type=object_storage_type, keystore_entries=keystore_entries
        ):
            event.defer()
            return

        if (
            object_storage_type == "s3-pcluster"
            and self.charm.snapshots_manager.is_custom_s3_ca_stored()
        ):
            self.charm.snapshots_manager.store_s3_ca(s3_tls_ca_chain=None)
            if self.charm.request_opensearch_restart(reason="clean up the object storage CA"):
                return

    # Helpers

    def _cleanup(
        self, object_storage_type: ObjectStorageType | None, keystore_entries: list[str]
    ) -> bool:
        """Cleanup the object storage stored configuration."""
        if not object_storage_type:
            return True

        try:
            self.charm.snapshots_manager.remove_repo(object_storage_type=object_storage_type)
            if keystore_entries:
                self.charm.keystore.remove_entries(keystore_entries)
                if not self.charm.keystore.reload():
                    return False
            self.charm.peers_data.delete(Scope.UNIT, "snapshot-object-storage-type")
            return True
        except OpenSearchHttpError as e:
            logger.error("Cleanup of the %s cluster config failed: %s", object_storage_type, e)
            return False

    def _grant_snapshots_secret_to_peer_consumers(self, secret_id: str) -> None:
        """Grant the snapshots secret to peer-cluster consumers."""
        try:
            sec = self.charm.model.get_secret(id=secret_id)
        except Exception as e:
            logger.warning("[snapshots/grant] load secret %s failed: %s", secret_id, e)
            return

        rels = list(self.charm.model.relations.get(PeerClusterRelationName, []))
        if not rels:
            logger.debug("[snapshots/grant] no peer-cluster relations to grant")
            return

        for rel in rels:
            try:
                sec.grant(rel)
                logger.info("[snapshots/grant] granted secret to peer relation id=%s", rel.id)
            except Exception as e:
                logger.warning("[snapshots/grant] grant to rel %s failed: %s", rel.id, e)

    def _publish_snapshots_secret(
        self, object_storage_type: Literal["s3", "azure", "gcs"], cfg: ObjectStorageConfig
    ) -> None:
        """Publish plugin secret with keystore keys + repo info to sub-clusters, and persist secret_id."""

        logger.debug("[snapshots] publish secret: type=%s", object_storage_type)

        # helpers to pull raw rel data
        def _s3_raw():
            info = self.s3_requirer.get_s3_connection_info() or {}
            logger.debug("[snapshots] info=%s", info)
            return {
                "bucket": info.get("bucket"),
                "base_path": info.get("path") or info.get("base-path") or info.get("base_path"),
                "region": info.get("region"),
                "endpoint": info.get("endpoint"),
                "tls_ca_chain": info.get("tls-ca-chain") or info.get("tls_ca_chain"),
            }

        def _azure_raw():
            info = self.azure_requirer.get_azure_storage_connection_info() or {}
            logger.debug("[snapshots] info=%s", info)
            return {
                "container": info.get("container"),
                "base_path": info.get("path") or info.get("base-path") or info.get("base_path"),
            }

        rel_name = None
        payload: dict[str, Any] | None = None

        if object_storage_type == "s3" and cfg.s3:
            c = cfg.s3.credentials
            keys = {
                "s3.client.default.access_key": c.access_key,
                "s3.client.default.secret_key": c.secret_key,
            }
            # grab region/endpoint from cfg if present
            if cfg.s3.region:
                keys["s3.client.default.region"] = cfg.s3.region
            if cfg.s3.endpoint:
                keys["s3.client.default.endpoint"] = cfg.s3.endpoint

            # get repo info from cfg
            raw = _s3_raw()
            bucket = cfg.s3.bucket or raw["bucket"]
            base_path = cfg.s3.base_path or raw["base_path"]
            tls_ca_chain = cfg.s3.tls_ca_chain or raw["tls_ca_chain"]

            if not bucket:
                logger.warning(
                    "[snapshots] s3 publish: missing bucket in cfg and relation; not publishing"
                )
                return

            payload = {
                "keys": keys,
                "repo": {"type": "s3", "bucket": bucket, "base_path": base_path or ""},
            }
            if tls_ca_chain:
                payload["tlscachain"] = tls_ca_chain

            rel_name = S3_RELATION

        elif object_storage_type == "azure" and cfg.azure:
            c = cfg.azure.credentials
            keys = {
                "azure.client.default.account": c.storage_account,
                "azure.client.default.key": c.secret_key,
            }

            raw = _azure_raw()
            container = cfg.azure.container or raw["container"]
            base_path = cfg.azure.base_path or raw["base_path"]

            if not container:
                logger.warning(
                    "[snapshots] azure publish: missing container in cfg and relation; not publishing"
                )
                return

            payload = {
                "keys": keys,
                "repo": {"type": "azure", "container": container, "base_path": base_path or ""},
            }
            rel_name = AZURE_RELATION

        elif object_storage_type == "gcs" and cfg.gcs:
            payload = {
                "keys": {},
                "repo": {
                    "type": "gcs",
                    "bucket": cfg.gcs.bucket,
                    "base_path": cfg.gcs.base_path or "",
                },
            }
            rel_name = GCS_RELATION

        else:
            logger.debug("[snapshots] publish: no cfg for %s", object_storage_type)
            return

        # track list of keystore keys for local cleanup
        self.charm.plugin_manager.put_plugin_config(
            scope=Scope.UNIT,
            label=SNAPSHOTS_SECRET_LABEL,
            cleanup={"keys": list(payload.get("keys", {}).keys())},
        )

        logger.info(
            "[snapshots] publishing secret label=%s rel=%s repo.type=%s repo=%s keys=%s ca=%s",
            SNAPSHOTS_SECRET_LABEL,
            rel_name,
            payload["repo"]["type"],
            {k: v for k, v in payload["repo"].items() if k != "type"},
            list(payload.get("keys", {}).keys()),
            bool(payload.get("tlscachain")),
        )

        # Juju secrets must be str -> str. Hence, store a single JSON blob.
        content = {"payload": json.dumps(payload)}

        secret_id = store_plugin_secret(self.charm, content=content, label=SNAPSHOTS_SECRET_LABEL)
        if not secret_id:
            logger.warning("[snapshots] secret publish failed; not updating APP plugin record")
            return

        # publish in APP scope so consumers discover secret_id via peer-cluster
        self.charm.plugin_manager.put_plugin_config(
            scope=Scope.APP,
            label=SNAPSHOTS_SECRET_LABEL,
            secret_id=secret_id,
            relation_name=rel_name,
        )
        logger.info(
            "[snapshots] published secret id=%s label=%s scope=%s",
            secret_id,
            SNAPSHOTS_SECRET_LABEL,
            Scope.APP,
        )

        # grant to peer-cluster consumers
        self._grant_snapshots_secret_to_peer_consumers(secret_id)
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            logger.debug("[snapshots] refreshing peer-cluster relation data (provider)")
            self.charm.peer_cluster_provider.refresh_relation_data(event=None, can_defer=False)

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handler for create backup action."""
        if error_message := self._action_missing_pre_requisites():
            event.fail(error_message)
            return

        try:
            snapshot_id = self.charm.snapshots_manager.create_snapshot(
                object_storage_type=self.object_storage_type
            )
        except OpenSearchHttpError as e:
            logger.error("Could not create a new snapshot: %s", e)
            event.fail(f"Backup request failed with: {str(e)}")
            return

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
        """Handler for list backups action."""
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

        try:
            _, indices_failed_to_close = (
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

    # Computed properties

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
                    # self.charm.model.get_relation(GCS_RELATION),
                ]
                if rel
            ]
            if len(active_rels) > 1:
                return "conflict"
            if self.charm.model.get_relation(S3_RELATION):
                return "s3"
            if self.charm.model.get_relation(AZURE_RELATION):
                return "azure"
            # if self.charm.model.get_relation(GCS_RELATION):
            #     return "gcs"
            if typ := self.charm.peers_data.get(Scope.UNIT, "snapshot-object-storage-type"):
                return typ
            return None

        # for sub-clusters, we rely on plugin secret to set the local type marker
        typ = self.charm.peers_data.get(Scope.UNIT, "snapshot-object-storage-type")
        if typ:
            logger.debug("[snapshots/ost] found local type marker: %s", typ)
            return typ

        logger.debug("[snapshots/ost] no local type marker, attempting bootstrap from APP secret")
        if self._bootstrap_from_app_secret():
            typ = self.charm.peers_data.get(Scope.UNIT, "snapshot-object-storage-type")
            logger.info("[snapshots/ost] bootstrap set type marker to: %s", typ)
            return typ

        logger.debug("[snapshots/ost] bootstrap failed or not applicable")
        return None

    @property
    def object_storage_config(self) -> ObjectStorageConfig | None:
        """Fetch the object storage data depending on the relation or plugin secret marker."""
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

        # if object_storage_type == "gcs":
        #     gcs_rel = self.charm.model.get_relation(GCS_RELATION)
        #     if not gcs_rel or not gcs_rel.app:
        #         return None
        #     return None

        return None

    # -----------------------------
    # Prechecks & repo ensure
    # -----------------------------

    def _action_missing_pre_requisites(  # noqa C901
        self, report_running_operations: bool = True
    ) -> str | None:
        """Compute the missing prerequisites for running a snapshot/restore action."""
        if not self.charm.unit.is_leader():
            logger.debug("[snapshots] precheck: not leader")
            return "Backup/Restore related actions must be run on the juju leader unit."

        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep:
            logger.debug("[snapshots] precheck: deployment not ready")
            return "Deployment not ready."

        if self.charm.upgrade_in_progress:
            logger.debug("[snapshots] precheck: upgrade in progress")
            return "Backup/Restore operations not supported while upgrade in-progress."

        ost = self.object_storage_type
        logger.debug("[snapshots] precheck: object_storage_type=%s", ost)
        if not ost:
            logger.warning(
                "[snapshots/precheck] no object storage type; trying last-resort bootstrap"
            )
            if self._bootstrap_from_app_secret():
                ost = self.object_storage_type
                logger.info("[snapshots/precheck] bootstrap succeeded; ost=%s", ost)
            if not ost:
                logger.error("[snapshots/precheck] still no storage type after bootstrap")
                return "Missing relation with an object storage integrator."

        if ost == "conflict":
            return "Conflict: more than one object storage integrators integrated."

        if not self.charm.opensearch.is_node_up() and not self.charm.alt_hosts:
            return "Connectivity issue: the opensearch service is not reachable."

        repo_name = self.charm.snapshots_manager.repository_name(ost)
        logger.debug(
            "[snapshots/precheck] type=%s repo=%s alt_hosts=%s",
            ost,
            self.charm.snapshots_manager.repository_name(ost),
            self.charm.alt_hosts,
        )

        try:
            if not self.charm.snapshots_manager.is_repository_created(ost):
                osc = self.object_storage_config
                logger.debug("[snapshots] precheck: repo missing; osc=%s", osc)
                if not osc:
                    logger.info("[snapshots] repo %s missing; attempting create.", repo_name)
                    return "Object storage configuration not ready."
                logger.info(f"[snapshots] repo {repo_name} missing; attempting create.")
                self.charm.snapshots_manager.create_repo(ost, osc)
                if not self.charm.snapshots_manager.is_repository_created(ost):
                    return "The opensearch repository has not been created yet."
        except OpenSearchHttpError as e:
            logger.debug("[snapshots] precheck: exception while verifying repo: %s", e)
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
            logger.debug("[snapshots] precheck: exception while checking operations: %s", e)
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

    def _bootstrap_from_app_secret(self) -> bool:
        """On a sub-cluster, try to reconstruct storage type + repo from the APP plugin secret."""
        logger.debug("[snapshots/bootstrap] entering bootstrap_from_app_secret")

        # only sub-clusters need bootstrapping
        if not self.charm.opensearch_peer_cm.is_consumer(of="main"):
            logger.debug("[snapshots/bootstrap] not a consumer of 'main', skipping")
            return False

        # read the APP-scoped plugin record which is written by the provider
        app_plugins = self.charm.state.app.plugin_config_info
        if SNAPSHOTS_SECRET_LABEL not in app_plugins:
            logger.debug(
                "[snapshots/bootstrap] APP plugin_config_info lacks '%s'", SNAPSHOTS_SECRET_LABEL
            )
            return False

        plugin = app_plugins[SNAPSHOTS_SECRET_LABEL]
        if not plugin.secret_id:
            logger.debug(
                "[snapshots/bootstrap] APP plugin '%s' has no secret_id", SNAPSHOTS_SECRET_LABEL
            )
            return False

        logger.info("[snapshots/bootstrap] fetching APP secret id=%s", plugin.secret_id)

        try:
            content = self.charm.model.get_secret(id=plugin.secret_id).get_content()
        except Exception as e:
            logger.warning(
                "[snapshots/bootstrap] failed to read APP secret id=%s: %s", plugin.secret_id, e
            )
            return False

        payload = self.parse_secret_content(content)
        if not payload:
            logger.warning("[snapshots/bootstrap] secret content could not be decoded")
            return False

        keys = payload.get("keys", {})
        repo = payload.get("repo", {})
        tls_ca_chain = payload.get("tlscachain")
        logger.info(
            "[snapshots/bootstrap] decoded secret: keys=%d, repo=%s", len(keys), repo.get("type")
        )

        # write keys to keystore
        if keys:
            logger.debug("[snapshots/bootstrap] adding %d keys to keystore", len(keys))
            self.charm.keystore.add_entries(keys)
            if not self.charm.keystore.reload():
                logger.warning("[snapshots/bootstrap] keystore reload failed; will retry later")
                return False
            logger.debug("[snapshots/bootstrap] keystore reloaded successfully")

        obj_type_marker = None
        obj_cfg = None

        if repo.get("type") == "s3":
            # pull creds from keystore keys and pass them to the model
            # Use empty strings not to get a Pydantic validation error
            access_key = keys.get("s3.client.default.access_key") or ""
            secret_key = keys.get("s3.client.default.secret_key") or ""
            region = keys.get("s3.client.default.region") or ""
            endpoint = keys.get("s3.client.default.endpoint") or ""
            bucket = (repo.get("bucket") or "").strip()
            base_path = (repo.get("base_path") or "").strip()

            obj_type_marker = "s3-pcluster"
            if tls_ca_chain:
                logger.debug(
                    "[snapshots/bootstrap] storing S3 CA chain (len=%d)", len(tls_ca_chain)
                )
                self.charm.snapshots_manager.store_s3_ca(tls_ca_chain)

            obj_cfg = ObjectStorageConfig(
                s3=S3RelData.from_dict(
                    {
                        "credentials": {
                            "access-key": access_key,
                            "secret-key": secret_key,
                        },
                        "bucket": bucket,
                        "base-path": base_path,
                        "region": region,
                        "endpoint": endpoint,
                        "tls-ca-chain": tls_ca_chain,
                    }
                )
            )

        elif repo.get("type") == "azure":
            account = keys.get("azure.client.default.account") or ""
            secret = keys.get("azure.client.default.key") or ""
            container = (repo.get("container") or "").strip()
            base_path = (repo.get("base_path") or "").strip()

            obj_type_marker = "azure-pcluster"
            obj_cfg = ObjectStorageConfig(
                azure=AzureRelData.from_dict(
                    {
                        "credentials": {
                            "storage-account": account,
                            "secret-key": secret,
                        },
                        "container": container,
                        "base-path": base_path,
                    }
                )
            )

        elif repo.get("type") == "gcs":
            bucket = (repo.get("bucket") or "").strip()
            base_path = (repo.get("base_path") or "").strip()

            obj_type_marker = "gcs-pcluster"
            obj_cfg = ObjectStorageConfig(
                gcs=GcsRelData.from_dict(
                    {
                        "credentials": {},
                        "bucket": bucket,
                        "base-path": base_path,
                    }
                )
            )
        else:
            logger.warning("[snapshots/bootstrap] unsupported repo type: %s", repo.get("type"))
            return False

        logger.info("[snapshots/bootstrap] setting local storage marker: %s", obj_type_marker)
        self.charm.peers_data.put(Scope.UNIT, "snapshot-object-storage-type", obj_type_marker)

        # ensure repository
        try:
            if not self.charm.snapshots_manager.is_repository_created(obj_type_marker):
                logger.info(
                    "[snapshots/bootstrap] repo missing; creating repo for %s", obj_type_marker
                )
                self.charm.snapshots_manager.create_repo(obj_type_marker, obj_cfg)
            else:
                logger.debug("[snapshots/bootstrap] repo already exists for %s", obj_type_marker)
        except OpenSearchHttpError as e:
            logger.error("[snapshots/bootstrap] repo ensure failed: %s", e)
            return False

        logger.info("[snapshots/bootstrap] completed successfully for %s", obj_type_marker)
        return True


class OpenSearchSnapshotsManager:
    """Manager class for Backups (snapshots)."""

    def __init__(self, charm: "OpenSearchBaseCharm", opensearch: "OpenSearchDistribution"):
        self.charm = charm
        self.opensearch = opensearch

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def create_repo(
        self,
        object_storage_type: ObjectStorageType,
        object_storage_config: ObjectStorageConfig,
        name: str | None = None,
    ) -> str:
        """Create an opensearch repository for storing backups."""
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
        # elif object_storage_type in {"gcs", "gcs-pcluster"}:
        #     settings = {
        #         "bucket": object_storage_config.gcs.bucket,
        #         "base_path": object_storage_config.gcs.base_path,
        #     }
        repo_type = self._repo_type(object_storage_type)
        response = self.opensearch.request(
            "PUT",
            f"_snapshot/{repo_name}?verify=false",
            payload={"type": repo_type, "settings": settings},
        )
        logger.debug("Snapshot repository creation response: %s", response)
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
            logger.debug("Snapshot repository deletion response: %s", response)
            assert response.get("acknowledged") is True
        except OpenSearchHttpError as e:
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

        response = self.opensearch.request(
            "PUT",
            f"_snapshot/{repo_name}/{snapshot_id}?wait_for_completion=false",
            payload={"indices": indices_clause},
            alt_hosts=self.charm.alt_hosts,
            timeout=30,
        )
        logger.info(f"Snapshot request submitted with backup-id: {snapshot_id}")
        logger.debug(f"Create snapshot request with id: {snapshot_id} - response: {response}")
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

        ignore = [f"-{idx}" for idx in SYSTEM_INDICES]
        indices_clause = ",".join(["*"] + ignore)
        restore_id = f"restore:{datetime.now().strftime(OPENSEARCH_BACKUP_ID_FORMAT).lower()}-snapshot:{snapshot_id}"

        restore_resp = self.opensearch.request(
            "POST",
            f"_snapshot/{repo_name}/{snapshot_id}/_restore?wait_for_completion=true",
            headers={"X-Opaque-Id": restore_id},
            payload={"indices": indices_clause},
            alt_hosts=self.charm.alt_hosts,
        )
        logger.info("Restore of snapshot '%s' response: %s", snapshot_id, restore_resp)
        assert restore_resp["snapshot"] == snapshot_id

        recovery_resp: list[dict[str, str]] = self.opensearch.request(
            "GET", "_cat/recovery?format=json"
        )
        snapshot_recoveries = [
            r
            for r in recovery_resp
            if (
                r["type"] == "snapshot"
                and r["repository"] == repo_name
                and r["snapshot"] == snapshot_id
            )
        ]
        restored_indices = set([r["index"] for r in snapshot_recoveries if r["stage"] == "done"])
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
        # return "gcs-repository"
        return None

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
        try:
            stored_cacerts = (
                list_cas(
                    store_pwd="changeit", store_path=f"{self.opensearch.paths.certs}/cacerts.p12"
                )
                or {}
            )
        except Exception:
            # if the keystore doesn't exist yet or list_cas fails, treat as CA is not stored
            stored_cacerts = {}

        if not s3_ca_chain:
            return "s3-snapshots-gateway" in stored_cacerts
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
            try:
                remove_ca(
                    alias="s3-snapshots-gateway",
                    store_pwd="changeit",
                    store_path=f"{self.opensearch.paths.certs}/cacerts.p12",
                )
            except Exception:
                logger.warning("[plugins/peer] unable to remove s3-snapshots-gateway")
                pass

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def should_restart_for_full_setup(
        self, object_storage_type: ObjectStorageType, object_storage_config: ObjectStorageConfig
    ) -> bool:
        """Check if a restart is needed for full setup."""
        if not self.opensearch.is_started():
            return False

        try:
            test_repo = f"tmp-{self.charm.unit_name}-{self.repository_name(object_storage_type)}"
            self.create_repo(object_storage_type, object_storage_config, name=test_repo)
            try:
                self.opensearch.request(
                    "DELETE", f"_snapshot/{test_repo}", alt_hosts=self.charm.alt_hosts
                )
            except Exception:
                logger.warning("[plugins/peer] unable to remove tmp-snapshot")
                pass
            logger.debug("[plugins/peer] no restart needed")
            return False
        except OpenSearchHttpError as e:
            if e.response_body.get("error", {}).get("type") == "repository_verification_exception":
                logger.debug("[plugins/peer] restart needed")
                return True
            raise

    def _repo_type(self, object_storage_type: ObjectStorageType) -> str:
        if object_storage_type in {"s3", "s3-pcluster"}:
            return "s3"
        if object_storage_type in {"azure", "azure-pcluster"}:
            return "azure"
        # if object_storage_type in {"gcs", "gcs-pcluster"}:
        #     return "gcs"
