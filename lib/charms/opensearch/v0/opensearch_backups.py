# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Backup.

This library holds the implementation of the OpenSearchBackup class, as well as the state enum
and configuration. It contains all the components for both small and large deployments.

###########################################################################################
#
# Small deployments
#
###########################################################################################

The class listens to both relation changes from [AZURE_RELATION | S3_RELATION]
and API calls and responses. The corresponding OpenSearchS3Plugin or OpenSearchAzurePlugin holds
the configuration info. The classes together manage the events related to backup/restore cycles.

The removal of backup only reverses step the API calls, to avoid accidentally deleting the
existing snapshots in the S3/Azure repo.

The main class to interact with is the OpenSearchMainBackup. This class will observe the S3 or
azure relation and backup-related actions.

OpenSearchMainBackup finishes the config of the backup service once has been set/unset and a
restart has been applied. That means, in the case s3/azure has been related,
this class will apply the new configuration to opensearch.yml and keystore.
After that, if unit is leader: execute the API calls to setup the backup using the manager.

A charm implementing this class must setup the following:

--> metadata.yaml
    ...

s3-credentials:
    interface: s3
    limit: 1
  azure-credentials:
    interface: azure
    limit: 1


--> main charm file
    ...

from charms.opensearch.v0.opensearch_backups import OpenSearchBackup, backup


class OpenSearchBaseCharm(CharmBase):
    def __init__(...):
        ...
        self.backup = backup(self)

###########################################################################################
#
# Large deployments
#
###########################################################################################

For developers, there is no meaningful difference between small and large deployments.
They both use the same backup() to return the correct object for their case.

The large deployments expands the original concept of OpenSearch backup to include other
juju applications that are not cluster_manager. This means a cluster may be a data-only or
even a failover cluster-manager and still interacts with s3/azure-integrator at a certain level.

The baseline is that every unit in the cluster must import the S3/azure credentials. The main
orchestrator will share these credentials via the peer-cluster relation. Failover and data
clusters will import that information from the peer-cluster relation.

To implement the points above without causing too much disruption to the existing code,
a factory pattern has been adopted, where the main charm receives a OpenSearchBackupBase
object that corresponds to its own case (cluster-manager, failover, data, etc).
"""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional, Set

import pydantic
from charms.data_platform_libs.v0.data_interfaces import RequirerData
from charms.data_platform_libs.v0.object_storage import AzureStorageRequires
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.opensearch.v0.constants_charm import (
    AZURE_RELATION,
    OPENSEARCH_BACKUP_ID_FORMAT,
    S3_RELATION,
    BackupConfigureStart,
    BackupDeferRelBrokenAsInProgress,
    BackupInDisabling,
    BackupRelDataIncomplete,
    BackupRelShouldNotExist,
    BackupSetupFailed,
    BackupSetupStart,
    PeerClusterRelationName,
    PluginConfigError,
    RestoreInProgress,
)
from charms.opensearch.v0.constants_secrets import (
    AZURE_PEER_SECRET_KEYS,
    S3_PEER_SECRET_KEYS,
)
from charms.opensearch.v0.helper_cluster import ClusterState, IndexStateEnum
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.models import AzureRelData, DeploymentType, Model, S3RelData
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
    OpenSearchNotFullyReadyError,
)
from charms.opensearch.v0.opensearch_keystore import (
    OpenSearchKeystoreError,
    OpenSearchKeystoreNotReadyError,
)
from charms.opensearch.v0.opensearch_locking import OpenSearchNodeLock
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchAzurePlugin,
    OpenSearchPluginMissingConfigError,
    OpenSearchPluginMissingDepsError,
    OpenSearchS3Plugin,
    PluginState,
)
from ops import (
    ActionEvent,
    BlockedStatus,
    MaintenanceStatus,
    Object,
    RelationEvent,
    SecretEvent,
    SecretNotFoundError,
    WaitingStatus,
)
from ops.framework import EventBase, EventSource, Handle
from overrides import override

# The unique Charmhub library identifier, never change it
LIBID = "d301deee4d2c4c1b8e30cd3df8034be2"

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


INDICES_TO_EXCLUDE_AT_RESTORE = {
    ".opendistro_security",
    ".opensearch-observability",
    OpenSearchNodeLock.OPENSEARCH_INDEX,
}


REPO_NOT_CREATED_ERR = "repository type does not exist"
REPO_NOT_ACCESS_ERR = "is not accessible"
REPO_CREATING_ERR = "Could not determine repository generation from root blobs"
RESTORE_OPEN_INDEX_WITH_SAME_NAME = "because an open index with same name already exists"


class OpenSearchBackupError(OpenSearchError):
    """Exception thrown when an opensearch backup-related action fails."""


class OpenSearchRestoreError(OpenSearchError):
    """Exception thrown when an opensearch restore-related action fails."""


class OpenSearchListBackupError(OpenSearchBackupError):
    """Exception thrown when internal list backups call fails."""


class OpenSearchRestoreCheckError(OpenSearchRestoreError):
    """Exception thrown when restore status check errors."""


class OpenSearchRestoreIndexClosingError(OpenSearchRestoreError):
    """Exception thrown when restore fails to close indices."""


class BackupServiceState(BaseStrEnum):
    """Enum for the states possible once plugin is enabled."""

    SUCCESS = "success"
    RESTORE_IN_PROGRESS = "restore in progress"
    RESPONSE_FAILED_NETWORK = "response failed: network error"
    REPO_NOT_CREATED = "repository not created"
    REPO_NOT_CREATED_ALREADY_EXISTS = "repo not created as it already exists"
    REPO_CREATION_ERR = "Failed creating repository"
    REPO_ERR_UNKNOWN = "Repository exception: unknown"
    REPO_MISSING = "repository is missing from request"
    REPO_UNREACHABLE = "backup repository is unreachable"
    ILLEGAL_ARGUMENT = "request contained wrong argument"
    SNAPSHOT_MISSING = "snapshot not found"
    SNAPSHOT_RESTORE_ERROR_INDEX_NOT_CLOSED = (
        "cannot restore, indices with same name are still open"
    )
    SNAPSHOT_RESTORE_ERROR = "restore of snapshot failed"
    SNAPSHOT_IN_PROGRESS = "snapshot in progress"
    SNAPSHOT_PARTIALLY_TAKEN = "snapshot partial: at least one shard missing"
    SNAPSHOT_INCOMPATIBILITY = "snapshot failed: incompatibility issues"
    SNAPSHOT_FAILED_UNKNOWN = "snapshot failed for unknown reason"


class BackupManager:
    """API related requests service for Opensearch"""

    def __init__(self, charm: "OpenSearchBaseCharm", repository: str | None = None):
        self.charm = charm
        self.repository = repository

    def backup(self, new_backup_id: str) -> Dict[str, Any]:
        """Runs the backup task in OpenSearch."""
        response = self.charm.opensearch.request(
            "PUT",
            f"_snapshot/{self.repository}/{new_backup_id.lower()}?wait_for_completion=false",
            payload={
                "indices": "*",  # Take all indices
                "partial": False,  # It is the default value, but we want to avoid partial backups
            },
            retries=6,
            timeout=10,
        )
        logger.info(f"Backup request submitted with backup-id {new_backup_id}")
        logger.debug(f"Create backup action request id {new_backup_id} response is: {response}")
        return response

    def restore(self, backup_id: str) -> Dict[str, Any]:
        """Runs the restore and processes the response."""
        backup_indices = self.list_backups().get(backup_id, {}).get("indices", {})
        output = self.charm.opensearch.request(
            "POST",
            f"_snapshot/{self.repository}/{backup_id.lower()}/_restore?wait_for_completion=true",
            payload={
                "indices": ",".join(
                    [f"-{idx}" for idx in INDICES_TO_EXCLUDE_AT_RESTORE & set(backup_indices)]
                ),
                "partial": False,  # It is the default value, but we want to avoid partial restores
            },
            retries=6,
            timeout=10,
        )
        logger.debug(f"_restore: restore call returned {output}")
        if (
            BackupManager.get_service_status(output)
            == BackupServiceState.SNAPSHOT_RESTORE_ERROR_INDEX_NOT_CLOSED
        ):
            # expected format for `reason`:
            # "[my-opensearch-repo:my-first-snapshot/dCK4Qth-TymRQ7Tu7Iga0g]
            #     cannot restore index [.opendistro-reports-definitions] because ..."
            to_close = output["error"]["reason"].split("[")[2].split("]")[0]
            raise OpenSearchRestoreIndexClosingError(f"_restore: fails to close {to_close}")

        if "snapshot" not in output or "shards" not in output.get("snapshot"):
            raise OpenSearchRestoreCheckError(f"_restore: unexpected response {output}")

        return output["snapshot"]

    def list_backups(self) -> dict[str, dict[str, Any]]:
        """Returns a mapping of snapshot ids / state."""
        # Using the original request method, as we want to raise an http exception if we
        # cannot get the snapshot list.
        response = self.charm.opensearch.request("GET", f"_snapshot/{self.repository}/_all")
        return {
            snapshot["snapshot"].upper(): {
                "state": snapshot["state"],
                "indices": snapshot.get("indices", []),
            }
            for snapshot in response.get("snapshots", [])
        }

    def clean(self):
        """Executes broken API calls."""
        return  # do not execute anything as we intend to keep the backups untouched

    def register(self, repo_settings: Dict[str, Any] | None) -> Dict[str, Any]:
        """Registers the snapshot repo in the cluster.

        Returns the Create/Update snapshot repo API response or raises an HTTP error.

        Raises:
          - ValueError
          - OpenSearchHttpError
        """
        if not repo_settings:
            raise ValueError("Backup repository settings missing.")

        response = self.charm.opensearch.request(
            "PUT",
            f"_snapshot/{self.repository}",
            payload={
                "type": "s3" if self.repository == S3_REPOSITORY else "azure",
                "settings": repo_settings,
            },
            retries=6,
            timeout=10,
        )
        return response

    def is_backup_in_progress(self) -> bool:
        """Returns True if backup is in progress, False otherwise.

        This method assumes that a relation already exists, so a check for active_relation != None
        should generally be done.

        We filter the _query_backup_status() and seek for the following states:
        - SNAPSHOT_IN_PROGRESS
        """
        if self.is_set() and self._query_backup_status() in [
            BackupServiceState.SNAPSHOT_IN_PROGRESS,
            BackupServiceState.RESPONSE_FAILED_NETWORK,
        ]:
            # We have a backup in progress or we cannot reach the API
            # taking the "safe path" of informing a backup is in progress
            return True
        return False

    def is_restore_in_progress(self) -> bool:
        """Checks if the restore is currently in progress."""
        if self.is_set() and self._query_restore_status() in [
            BackupServiceState.RESTORE_IN_PROGRESS,
            BackupServiceState.RESPONSE_FAILED_NETWORK,
        ]:
            # We have a restore in progress or we cannot reach the API
            # taking the "safe path" of informing a restore is in progress
            return True
        return False

    def is_backup_available_for_restore(self, backup_id: str) -> bool:
        """Checks if the backup_id exists and is ready for a restore."""
        backups = self.list_backups()
        try:
            return (
                backup_id in backups.keys()
                and BackupManager.get_snapshot_status(backups[backup_id]["state"])
                == BackupServiceState.SUCCESS
            )
        except OpenSearchListBackupError:
            return False

    def _close_indices(self, indices: Set[str]) -> bool:
        """Close a list of indices and return their status."""
        if not indices:
            # The indices is empty, we do not need to check
            return True
        resp = self.charm.opensearch.request(
            "POST",
            f"{','.join(indices)}/_close",
            payload={
                "ignore_unavailable": "true",
            },
            retries=6,
            timeout=10,
        )

        # Trivial case, something went wrong
        if not resp or not resp.get("acknowledged", False):
            return False

        # There are two options here we return True:
        # 1) ack=True and shards_ack=False with empty indices
        #    This means the indices are already closed
        if not resp.get("shards_acknowledged", False):
            if not resp.get("indices", {}):
                return True
            return False

        # 2) ack=True and shards_ack=True with each index in resp["indices"]
        #    marked as closed=True
        # The statement of explicit "is True" below assures we have a boolean
        # as the response has the form of "true" or "false" originally
        all_closed = all(
            [state and state.get("closed") for state in resp.get("indices", {}).values()]
        )
        if not all_closed:
            return False

        # Finally, we can state it is all good
        return True

    def close_indices_if_needed(self, backup_id: str) -> Set[str]:
        """Closes indices that will be restored.

        Returns a set of indices that were closed or raises an exception:
        - OpenSearchRestoreIndexClosingError if any of the indices could not be closed.

        Raises:
            OpenSearchHttpError
            OpenSearchRestoreIndexClosingError
        """
        backup_indices = self.list_backups().get(backup_id, {}).get("indices", {})
        indices_to_close = set()
        for index, state in ClusterState.indices(self.charm.opensearch).items():
            if (
                index in backup_indices
                and state["status"] != IndexStateEnum.CLOSED
                and index not in INDICES_TO_EXCLUDE_AT_RESTORE
            ):
                indices_to_close.add(index)

        try:
            if not self._close_indices(indices_to_close):
                raise OpenSearchRestoreIndexClosingError()
        except OpenSearchError as e:
            raise OpenSearchRestoreIndexClosingError(e)
        return indices_to_close

    def _query_restore_status(self) -> BackupServiceState:
        try:
            indices_status = (
                self.charm.opensearch.request(
                    "GET",
                    "/_recovery?human",
                    retries=6,
                    timeout=10,
                )
                or {}
            )
            logger.debug(f"Restore status: {indices_status}")
        except OpenSearchHttpError as e:
            output = e.response_body if e.response_body else None
            return BackupManager.get_service_status(output)
        except Exception as e:
            logger.error(f"_query_restore_status failed with: {e}")
            return BackupServiceState.RESPONSE_FAILED_NETWORK

        for info in indices_status.values():
            # Now, check the status of each shard
            for shard in info["shards"]:
                if shard["type"] == "SNAPSHOT" and shard["stage"] != "DONE":
                    return BackupServiceState.RESTORE_IN_PROGRESS
        return BackupServiceState.SUCCESS

    def _query_backup_status(self, backup_id: Optional[str] = None) -> BackupServiceState:
        """Return the state of the backup service."""
        try:
            target = f"_snapshot/{self.repository}/"
            target += f"{backup_id.lower()}" if backup_id else "_all"
            output = self.charm.opensearch.request(
                "GET",
                target,
                retries=6,
                timeout=10,
            )
            logger.debug(f"Backup status: {output}")
        except OpenSearchHttpError as e:
            output = e.response_body if e.response_body else None
        except Exception as e:
            logger.error(f"_query_backup_status failed with: {e}")
            return BackupServiceState.RESPONSE_FAILED_NETWORK

        return BackupManager.get_service_status(output)

    def is_set(self) -> bool:
        """Checks if the backup system is set by querying the cluster.

        Raises:
            OpenSearchHttpError: cluster is unreachable
        """
        try:
            output = self.charm.opensearch.request(
                "GET",
                f"_snapshot/{self.repository}",
                retries=6,
                timeout=10,
            )
        except OpenSearchHttpError as e:
            output = e.response_body if e.response_body else None
        if not output:
            return False
        return BackupManager.get_service_status(output) not in [
            BackupServiceState.REPO_NOT_CREATED,
            BackupServiceState.REPO_MISSING,
        ]

    def is_idle(self) -> bool:
        """Checks if the backup system is idle."""
        return not self.is_backup_in_progress() and not self.is_restore_in_progress()

    @staticmethod
    def check_snapshot_status(charm) -> BackupServiceState:
        """Check the snapshot."""
        try:
            response = charm.opensearch.request(
                "GET",
                "/_snapshot/_status",
                retries=6,
                timeout=10,
            )
            return BackupManager.get_snapshot_status(response)
        except OpenSearchHttpError:
            return BackupServiceState.RESPONSE_FAILED_NETWORK

    @staticmethod
    def get_service_status(response: dict[str, Any] | None) -> BackupServiceState:  # noqa: C901
        """Returns the response status in a Enum.

        Based on:
        https://github.com/opensearch-project/OpenSearch/blob/
            ba78d93acf1da6dae16952d8978de87cb4df2c61/
            server/src/main/java/org/opensearch/OpenSearchServerException.java#L837
        https://github.com/opensearch-project/OpenSearch/blob/
            ba78d93acf1da6dae16952d8978de87cb4df2c61/
            plugins/repository-s3/src/yamlRestTest/resources/rest-api-spec/test/repository_s3/40_repository_ec2_credentials.yml
        """
        if not response:
            return BackupServiceState.SNAPSHOT_FAILED_UNKNOWN

        try:
            if "error" not in response:
                return BackupServiceState.SUCCESS

            if "root_cause" not in response["error"]:
                return BackupServiceState.REPO_ERR_UNKNOWN

            error_type = response["error"]["root_cause"][0]["type"]
            reason = response["error"]["root_cause"][0]["reason"]
            logger.warning(f"response contained error: {error_type} - {reason}")
        except (KeyError, IndexError) as e:
            logger.exception(e)
            logger.error("response contained unknown error code")
            return BackupServiceState.RESPONSE_FAILED_NETWORK

        # Check if we errored b/c s3 repo is not configured, hence we are still
        # waiting for the plugin to be configured
        match error_type:
            case "repository_exception" if REPO_NOT_CREATED_ERR in reason:
                return BackupServiceState.REPO_NOT_CREATED
            case "repository_exception" if REPO_CREATING_ERR in reason:
                return BackupServiceState.REPO_CREATION_ERR
            case "repository_exception":
                return BackupServiceState.REPO_ERR_UNKNOWN
            case "repository_missing_exception":
                return BackupServiceState.REPO_MISSING
            case "repository_verification_exception" if REPO_NOT_ACCESS_ERR in reason:
                return BackupServiceState.REPO_UNREACHABLE
            case "illegal_argument_exception":
                return BackupServiceState.ILLEGAL_ARGUMENT
            case "snapshot_missing_exception":
                return BackupServiceState.SNAPSHOT_MISSING
            case "snapshot_restore_exception" if RESTORE_OPEN_INDEX_WITH_SAME_NAME in reason:
                return BackupServiceState.SNAPSHOT_RESTORE_ERROR_INDEX_NOT_CLOSED
            case "snapshot_restore_exception":
                return BackupServiceState.SNAPSHOT_RESTORE_ERROR
            case _:
                # There is an error, but we could not specify which
                return BackupServiceState.REPO_ERR_UNKNOWN

    @staticmethod
    def get_snapshot_status(response: Dict[str, Any] | None) -> BackupServiceState:
        """Returns the snapshot status."""
        if not response:
            return BackupServiceState.SNAPSHOT_FAILED_UNKNOWN
        # Now, check snapshot status:
        r_str = str(response)
        if "IN_PROGRESS" in r_str:
            return BackupServiceState.SNAPSHOT_IN_PROGRESS
        if "PARTIAL" in r_str:
            return BackupServiceState.SNAPSHOT_PARTIALLY_TAKEN
        if "INCOMPATIBLE" in r_str:
            return BackupServiceState.SNAPSHOT_INCOMPATIBILITY
        if "FAILED" in r_str:
            return BackupServiceState.SNAPSHOT_FAILED_UNKNOWN
        return BackupServiceState.SUCCESS


class _DisableBackupRelationEvent(EventBase):
    """Informs there is a backup relation going away and must be proceeded.

    The main issue this event resolves is the fact we may have a relation going away during a
    backup / restore. If that is the case, then we need to be able to defer the event until the
    backup / restore is finished.

    Why not deferring the RelationBroken?

    Because the RelationBroken will carry relation data only at the moment the event is called.
    After that, we cannot guarantee anything about the relation broken event. Therefore, we will
    replace it with a custom event that will carry the relation name and the relation data.
    """

    def __init__(self, handle: Handle, relation_name: str):
        super().__init__(handle)
        self.relation_name = relation_name

    @override
    def snapshot(self) -> Dict[str, Any]:
        """Return the snapshot data that should be persisted.

        Subclasses must override to save any custom state.
        """
        result = super().snapshot()
        result["relation_name"] = self.relation_name
        return result

    @override
    def restore(self, snapshot: Dict[str, Any]):
        """Restore the value state from the given snapshot.

        Subclasses must override to restore their custom state.
        """
        super().restore(snapshot)
        self.relation_name = snapshot["relation_name"]


class OpenSearchBackupBase(Object):
    """Works as parent for all backup classes.

    This class does a smooth transition between orchestrator and non-orchestrator clusters.
    """

    _disable_backup_event = EventSource(_DisableBackupRelationEvent)

    def __init__(self, charm: "OpenSearchBaseCharm", relation_name: str = PeerClusterRelationName):
        """Initializes the opensearch backup base.

        This class will not hold a s3_client or object_storage object, as it is not intended to
        really manage the relation besides waiting for the deployment description.
        """
        super().__init__(charm, relation_name)
        self.charm = charm
        self.relation_name = relation_name
        self.backup_manager = BackupManager(charm, repository=self.repository)

        self.framework.observe(self._disable_backup_event, self._on_backup_disable)

        # We can reuse the same method, as the plugin manager will apply configs accordingly.
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)
        self.framework.observe(self.charm.on.secret_remove, self._on_secret_changed)

        for relation in (S3_RELATION, AZURE_RELATION):
            for event in [
                self.charm.on[relation].relation_joined,
                self.charm.on[relation].relation_changed,
                self.charm.on[relation].relation_departed,
                self.charm.on[relation].relation_broken,
            ]:
                self.framework.observe(event, self._on_backup_relation_event)
            self.framework.observe(
                self.charm.on[relation].relation_created, self._on_backup_relation_created
            )
            self.framework.observe(
                self.charm.on[relation].relation_broken, self._on_backup_relation_broken
            )

        for event in [
            self.charm.on.create_backup_action,
            self.charm.on.list_backups_action,
            self.charm.on.restore_action,
        ]:
            self.framework.observe(event, self._on_backup_action)

    def _on_secret_changed(self, event: SecretEvent) -> None:
        pass

    def _on_backup_relation_event(self, event: RelationEvent) -> None:
        """Defers the backup relation events."""
        logger.info("Deployment description not yet available, deferring backup relation event")
        event.defer()

    def _on_backup_relation_created(self, _: RelationEvent) -> None:
        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )

    def _on_backup_relation_broken(self, event: RelationEvent) -> None:
        """Emits the backup disable event."""
        if event.relation.name in [S3_RELATION, AZURE_RELATION]:
            self._disable_backup_event.emit(
                relation_name=(
                    S3_RELATION if event.relation.name == S3_RELATION else AZURE_RELATION
                ),
            )
            return

        # We have a peer relation going away, so we still must clean up the keystore.
        # In this case, we must disable all backup systems, as the peer cluster always
        # carry all the information.

        # We disable both plugins
        plugins = [OpenSearchAzurePlugin(self.charm, None), OpenSearchS3Plugin(self.charm, None)]
        for plug in plugins:
            # We only catch the keystore not ready exception
            # This exception happens after the keystore itself has been cleaned but the API call
            # to reload failed.
            # In this case, we can ignore the exception and continue, as it will be called for
            # other units and the keystore is clean.
            # Any other exception should result in actual errors.
            try:
                self.charm.plugin_manager.apply_config(plug.disable())
            except OpenSearchKeystoreNotReadyError:
                if self.charm.opensearch.is_service_started():
                    # We have an application up and running but not responding
                    # We cannot defer either, so we will fail and retry later
                    raise
                logger.debug("Backup broken relation: keystore not ready yet")
                # No need to defer, we already cleaned the keystore.
                return

    def _on_backup_disable(self, event: _DisableBackupRelationEvent) -> None:  # noqa C901
        """Disables the backup relation."""
        self.charm.status.clear(BackupRelDataIncomplete)
        self.charm.status.clear(BackupRelShouldNotExist)
        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupRelShouldNotExist, app=True)

        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            event.defer()
            return

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            # Nothing to do besides fixing the status
            return

        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )

        if (
            self.charm.model.get_relation(event.relation_name)
            and self.charm.model.get_relation(event.relation_name).units
        ):
            # The main app units must defer this event
            # as they are related directly with the backup integrator
            # and they are still seeing data in the relation databag.
            event.defer()
            return

        self.charm.status.set(MaintenanceStatus(BackupInDisabling))
        # Check snapshot
        # This will call a generic GET /_snapshot/_status, independent of the repository type
        snapshot_status = BackupManager.check_snapshot_status(self.charm)
        if snapshot_status in [
            BackupServiceState.SNAPSHOT_IN_PROGRESS,
        ]:
            # 1) snapshot is either in progress or partially taken: block and defer this event
            self.charm.status.set(WaitingStatus(BackupDeferRelBrokenAsInProgress))
            event.defer()
            return
        self.charm.status.clear(BackupDeferRelBrokenAsInProgress)

        if snapshot_status in [
            BackupServiceState.SNAPSHOT_PARTIALLY_TAKEN,
        ]:
            logger.warning(
                "Snapshot has been partially taken, but not completed. Continuing with relation removal..."
            )

        # Run the check here, instead of the start of this hook, as we want all the
        # units to keep deferring the event if needed.
        # That avoids a condition where we have:
        # 1) A long snapshot is taking place
        # 2) Relation is removed
        # 3) Only leader is checking for that and deferring the event
        # 4) The leader is lost or removed
        # 5) The snapshot is removed: self._execute_s3_broken_calls() never happens
        # That is why we are running the leader check here and not at first
        if (
            self.charm.opensearch_peer_cm.deployment_desc().typ == DeploymentType.MAIN_ORCHESTRATOR
            and self.charm.unit.is_leader()
        ):
            # Run the API calls
            self.backup_manager.clean()

        plug = (
            OpenSearchAzurePlugin(self.charm, None)
            if event.relation_name == AZURE_RELATION
            else OpenSearchS3Plugin(self.charm, None)
        )

        try:
            self.charm.plugin_manager.apply_config(plug.disable())
        except OpenSearchKeystoreError:
            # The plugin is not present, we can ignore it
            logger.info(f"Error while removing {plug.name}")
            event.defer()
            return
        except OpenSearchError as e:
            self.charm.status.set(BlockedStatus(PluginConfigError))
            # There was an unexpected error, log it and block the unit
            logger.error(e)
            event.defer()
            return

        # Now, as this is related strictly to the MAIN orchestrator,
        # we must update any peer relation.
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

        self.charm.status.clear(BackupInDisabling)
        self.charm.status.clear(PluginConfigError)

    def _on_backup_action(self, event: ActionEvent) -> None:
        """No deployment description yet, fail any actions."""
        if not self.active_relation:
            event.fail("Failed: charm is not related to neither s3 nor azure")
            return

        logger.info("Deployment description not yet available, failing actions.")
        event.fail("Failed: deployment description not yet available")

    @property
    def repository(self) -> str | None:
        """Return the repository to set."""
        repository = None
        if self.active_relation == S3_RELATION:
            repository = S3_REPOSITORY
        if self.active_relation == AZURE_RELATION:
            repository = AZURE_REPOSITORY

        return repository

    @property
    def active_relation(self) -> str | None:
        """Check which relation is active and return its value."""
        s3_rel = self.model.get_relation(S3_RELATION)
        azure_rel = self.model.get_relation(AZURE_RELATION)

        # Both existing or both not existing is an exit condition.
        if (s3_rel is None and azure_rel is None) or (s3_rel and azure_rel):
            return None

        return S3_RELATION if s3_rel else AZURE_RELATION

    def _generate_backup_list_output(self, backups: Dict[str, Any]) -> str:
        """Generates a list of backups in a formatted table.

        List contains successful and failed backups in order of ascending time.

        Raises:
            OpenSearchError: if the list of backups errors
        """
        backup_list = []
        for _id, _backup in backups.items():
            state = BackupManager.get_snapshot_status(_backup["state"])
            backup_list.append((_id, state.value))

        output = ["{:<20s} | {:s}".format(" backup-id", "backup-status")]
        output.append("-" * len(output[0]))

        for backup_id, backup_status in backup_list:
            output.append("{:<20s} | {:s}".format(backup_id, backup_status))
        return "\n".join(output)


class OpenSearchNonOrchestratorClusterBackup(OpenSearchBackupBase):
    """Simpler implementation of backup relation for non-orchestrator clusters.

    In a nutshell, non-orchestrator clusters should receive the backup information via
    peer-cluster relation instead; and must fail any action or major backup relation events.

    This class means we are sure this juju app is a non-orchestrator. In this case, we must
    manage the update status correctly if the user ever tries to relate the backup credentials.
    """

    def __init__(self, charm: "OpenSearchBaseCharm", relation_name: str = PeerClusterRelationName):
        """Manager of OpenSearch backup relations."""
        super().__init__(charm, relation_name)

    @override
    def _on_secret_changed(self, event: SecretEvent) -> None:  # noqa: C901
        """Processes the secret changes."""
        try:
            if not any(
                [
                    k in S3_PEER_SECRET_KEYS + AZURE_PEER_SECRET_KEYS
                    for k in event.secret.get_content().keys()
                ]
            ):
                logger.info(
                    f"Secret not relevant for backups, abandoning secret id {event.secret.id}"
                )
                return
        except SecretNotFoundError:
            logger.warning("Secret not found, abandoning secret event")
            return

        if not (data := self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)):
            event.defer()
            return

        plugins = [
            OpenSearchS3Plugin(
                charm=self.charm,
                relation_data=data.credentials.s3,
            ),
            OpenSearchAzurePlugin(
                charm=self.charm,
                relation_data=data.credentials.azure,
            ),
        ]

        for plugin in plugins:
            # Early check to avoid trying to configure both with empty credentials
            if not plugin.data:
                continue
            try:
                if not self.charm.plugin_manager.is_ready_for_api():
                    raise OpenSearchNotFullyReadyError()
                self.charm.plugin_manager.apply_config(plugin.config())
            except (OpenSearchKeystoreNotReadyError, OpenSearchNotFullyReadyError):
                logger.info(f"{plugin.name}: not ready, we wait for another peer cluster.")
            except OpenSearchPluginMissingConfigError as e:
                logger.info(f"Missing configs for {plugin.name}: {e}")

        event.secret.get_content(refresh=True)

    @override
    def _on_backup_relation_event(self, event: RelationEvent) -> None:
        """Processes the non-orchestrator cluster events."""
        self.charm.status.set(BlockedStatus(BackupRelShouldNotExist))
        if self.charm.unit.is_leader():
            self.charm.status.set(BlockedStatus(BackupRelShouldNotExist), app=True)
        logger.info("Non-orchestrator cluster, abandon relation event")


class OpenSearchMainBackup(ABC, OpenSearchBackupBase):
    """Common class for the MAIN orchestrator backup component.

    This class removes the redundancy between several backup backend classes.
    """

    def __init__(self, charm: "OpenSearchBaseCharm", relation_name: str = S3_RELATION):
        """Manager of OpenSearch backup relations."""
        super().__init__(charm, relation_name)
        self.client = None

        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_backup_action)

    @abstractmethod
    def get_service_status(self, response: dict[str, Any] | None) -> BackupServiceState:
        """Extends the backup manager's service status check by incorporating relation data."""
        ...

    @property
    @abstractmethod
    def plugin(self):
        """Returns the plugin for this class."""
        ...

    @property
    @abstractmethod
    def data(self) -> Model | None:
        """Returns the data for the backup backend."""
        ...

    @property
    def _plugin_status(self):
        return self.charm.plugin_manager.status(self.plugin)

    @override
    def _on_backup_relation_event(self, event: RelationEvent) -> None:
        """Overrides the parent method to process the s3 relation events, as we use s3_client.

        We run the peer cluster orchestrator's refresh on every new s3 information.
        """
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    @override
    def _on_backup_action(self, event: ActionEvent) -> None:
        """Just overloads the base method, as we process each action in this class."""
        pass

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Returns the list of available backups to the user."""
        backups = {}
        try:
            backups = self.backup_manager.list_backups()
        except OpenSearchError as e:
            event.fail(
                f"List backups action failed - {str(e)} - check the application logs for the full stack trace."
            )
        if event.params.get("output").lower() == "json":
            event.set_results({"backups": json.dumps(backups)})
        elif event.params.get("output").lower() == "table":
            event.set_results({"backups": self._generate_backup_list_output(backups)})
        else:
            event.fail("Failed: invalid output format, must be either json or table")

    def _on_restore_backup_action(self, event: ActionEvent) -> None:  # noqa #C901
        """Restores a backup to the current cluster."""
        if self.charm.upgrade_in_progress:
            event.fail("Restore not supported while upgrade in-progress")
            return
        if not self.backup_manager.is_set():
            event.fail("Failed: backup service is not configured yet")
            return
        try:
            if not self.backup_manager.is_idle():
                event.fail("Failed: backup or restore is still in progress")
                return
        except OpenSearchRestoreCheckError:
            event.fail("Failed: error connecting to the cluster")
            return
        # Now, validate the backup is working
        backup_id = event.params.get("backup-id")
        if not self.backup_manager.is_backup_available_for_restore(backup_id):
            event.fail(f"Failed: no backup-id {backup_id}")
            return

        self.charm.status.set(MaintenanceStatus(RestoreInProgress))

        # Restore will try to close indices if there is a matching name.
        # The goal is to leave the cluster in a running state, even if the restore fails.
        # In case of failure, then restore action must return a list of closed indices
        try:
            closed_idx = self.backup_manager.close_indices_if_needed(backup_id)
            output = self.backup_manager.restore(backup_id)
            logger.debug(f"Restore action: received response: {output}")
            logger.info(f"Restore action succeeded for backup_id {backup_id}")
        except (
            OpenSearchHttpError,
            OpenSearchRestoreIndexClosingError,
            OpenSearchRestoreCheckError,
        ) as e:
            self.charm.status.clear(RestoreInProgress)
            event.fail(f"Failed: {e}")
            return

        # Post execution checks
        # Was the call successful?
        state = self.get_service_status(output)
        if state != BackupServiceState.SUCCESS:
            event.fail(f"Restore failed with {state}")
            self.charm.status.clear(RestoreInProgress)
            return

        shards = output.get("shards", {})
        if shards.get("successful", -1) != shards.get("total", 0):
            event.fail("Failed to restore all the shards")
            self.charm.status.clear(RestoreInProgress)
            return

        try:
            msg = (
                "Restore in progress..."
                if self.backup_manager.is_restore_in_progress()
                else "Restore is complete"
            )
        except OpenSearchRestoreCheckError:
            event.fail("Failed: error connecting to the cluster")
            return
        self.charm.status.clear(RestoreInProgress)
        event.set_results(
            {"backup-id": backup_id, "status": msg, "closed-indices": str(closed_idx)}
        )

    def _on_create_backup_action(self, event: ActionEvent) -> None:  # noqa: C901
        """Creates a backup from the current cluster."""
        if self.charm.upgrade_in_progress:
            event.fail("Backup not supported while upgrade in-progress")
            return
        if not self.backup_manager.is_set():
            event.fail("Failed: backup service is not configured")
            return
        if not self.backup_manager.is_idle():
            event.fail("Failed: backup service is busy")
            return

        new_backup_id = datetime.now().strftime(OPENSEARCH_BACKUP_ID_FORMAT)
        try:
            self.backup_manager.backup(new_backup_id)
        except (
            OpenSearchHttpError,
            OpenSearchListBackupError,
        ) as e:
            event.fail(f"Failed with exception: {e}")
            return
        event.set_results({"backup-id": new_backup_id, "status": "Backup is running."})

    def _on_backup_credentials_changed(self, event: EventBase) -> None:  # noqa: C901
        """Calls the plugin manager config handler.

        This method will iterate over the s3 relation and check:
        1) Is S3 fully configured? If not, we can abandon this event
        2) Try to enable the plugin
        3) If the plugin is not enabled, then defer the event
        4) Send the API calls to setup the backup service
        """
        if not self.plugin.requested_to_enable():
            # Always check if a relation actually exists and if options are available
            # in this case, seems one of the conditions above is not yet present
            # abandon this restart event, as it will be called later once s3 configuration
            # is correctly set
            self.charm.status.clear(PluginConfigError)
            self.charm.status.clear(BackupSetupStart)
            self.charm.status.clear(BackupRelDataIncomplete)
            return

        self.charm.status.set(MaintenanceStatus(BackupSetupStart))

        try:
            if not self.charm.plugin_manager.is_ready_for_api():
                raise OpenSearchNotFullyReadyError()
            self.charm.plugin_manager.apply_config(self.plugin.config())
        except (OpenSearchKeystoreNotReadyError, OpenSearchNotFullyReadyError):
            logger.warning("s3-changed: cluster not ready yet")
            event.defer()
            return
        except (OpenSearchPluginMissingConfigError, OpenSearchPluginMissingDepsError) as e:
            self.charm.status.set(BlockedStatus(BackupRelDataIncomplete))
            logger.error(e)
            return
        except OpenSearchError as e:
            self.charm.status.set(BlockedStatus(PluginConfigError))
            # There was an unexpected error, log it and block the unit
            logger.error(e)
            event.defer()
            return

        if self._plugin_status not in [
            PluginState.ENABLED,
            PluginState.WAITING_FOR_UPGRADE,
        ]:
            logger.warning("_on_s3_credentials_changed: plugin is not enabled.")
            event.defer()
            return

        if not self.charm.unit.is_leader():
            # Plugin is configured locally for this unit. Now the leader proceed.
            self.charm.status.clear(PluginConfigError)
            self.charm.status.clear(BackupSetupStart)
            self.charm.status.clear(BackupRelDataIncomplete)
            return

        # Leader configures this plugin
        try:
            self.apply_api_config_if_needed()
        except OpenSearchBackupError as e:
            # Finish here and wait for the user to reconfigure it and retrigger a new event
            logger.error(e)
            event.defer()
            return
        except pydantic.error_wrappers.ValidationError as e:
            logger.error(f"Failed to parse S3 relation data: {e}")
            # It means we are missing some data in the relation
            self.charm.status.set(BlockedStatus(BackupRelDataIncomplete))
            return
        self.charm.status.clear(PluginConfigError)
        self.charm.status.clear(BackupSetupStart)
        self.charm.status.clear(BackupRelDataIncomplete)

    def apply_api_config_if_needed(self) -> None:
        """Runs the post restart routine and API calls needed to setup/disable backup.

        This method should be called by the charm in its restart callback resolution.
        """
        if not self.charm.unit.is_leader():
            logger.debug("apply_api_config_if_needed: only leader can run this method")
            return
        # Backup relation has been recently made available with all the parameters needed.
        # Steps:
        #     (1) set up as maintenance;
        self.charm.status.set(MaintenanceStatus(BackupConfigureStart))

        #     (2) run the request; and
        try:
            snapshot_repo_resp = self.backup_manager.register(self.data)
            state = self.get_service_status(snapshot_repo_resp)
        except (ValueError, OpenSearchHttpError) as e:
            logger.error(f"Failed to setup backup service with exception: {e}")
            state = BackupServiceState.REPO_ERR_UNKNOWN

        #     (3) based on the response, set the message status
        if state != BackupServiceState.SUCCESS:
            logger.error(f"Failed to setup backup service with state {state}")
            self.charm.status.clear(BackupConfigureStart)
            self.charm.status.set(BlockedStatus(BackupSetupFailed))
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupSetupFailed), app=True)
            raise OpenSearchBackupError()

        self.charm.status.clear(BackupSetupFailed)
        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupSetupFailed, app=True)
        self.charm.status.clear(BackupConfigureStart)


class OpenSearchS3Backup(OpenSearchMainBackup):
    """Implements backup relation and API management."""

    def __init__(self, charm: "OpenSearchBaseCharm", relation_name: str = S3_RELATION):
        """Manager of OpenSearch backup relations."""
        super().__init__(charm, relation_name)
        self.client = S3Requirer(self.charm, S3_RELATION)
        self.framework.observe(
            self.client.on.credentials_changed, self._on_backup_credentials_changed
        )

    @property
    def _model(self) -> S3RelData | None:
        if relation := self.charm.model.get_relation(S3_RELATION):
            if data := S3RelData.from_relation(dict(relation.data[relation.app])):
                return data
        return None

    @property
    @override
    def plugin(self) -> OpenSearchS3Plugin:
        """Returns the plugin for this class."""
        try:
            if relation := self.charm.model.get_relation(S3_RELATION):
                if data := S3RelData.from_relation(dict(relation.data[relation.app])):
                    return OpenSearchS3Plugin(self.charm, data.credentials)
        except pydantic.error_wrappers.ValidationError as e:
            logger.error(f"Failed to parse S3 relation data: {e}")
        return OpenSearchS3Plugin(self.charm, relation_data=None)

    @property
    @override
    def data(self) -> Dict[str, Any] | None:
        """Returns the data for the backup backend."""
        if self._model:
            return self._model.dict(exclude={"tls_ca_chain", "credentials"})
        return None

    @override
    def get_service_status(self, response: dict[str, Any] | None) -> BackupServiceState:
        """Returns the response status in a Enum."""
        if (status := BackupManager.get_service_status(response)) == BackupServiceState.SUCCESS:
            return BackupServiceState.SUCCESS
        if (
            "bucket" in self.client.get_s3_connection_info()
            and S3_REPOSITORY in response
            and "settings" in response[self.repository]
            and self.client.get_s3_connection_info()["bucket"]
            == response[self.repository]["settings"]["bucket"]
        ):
            return BackupServiceState.REPO_NOT_CREATED_ALREADY_EXISTS
        return status


class OpenSearchAzureBackup(OpenSearchMainBackup):
    """Implements backup relation and API management."""

    def __init__(self, charm: "OpenSearchBaseCharm", relation_name: str = AZURE_RELATION):
        """Manager of OpenSearch backup relations."""
        super().__init__(charm, relation_name)
        self.client = AzureStorageRequires(self.charm, AZURE_RELATION)
        self.framework.observe(
            self.client.on.storage_connection_info_changed,
            self._on_backup_credentials_changed,
        )
        self._relation = self.charm.model.get_relation(AZURE_RELATION)

    @property
    def _model(self) -> AzureRelData | None:
        if endpoint_info := RequirerData(
            model=self.charm.model,
            relation_name=AZURE_RELATION,
            additional_secret_fields=["secret-key"],
        ):
            if (data := endpoint_info.fetch_relation_data()) and self._relation.id in data:
                return AzureRelData.from_relation(data[self._relation.id])
        return None

    @property
    @override
    def plugin(self) -> OpenSearchAzurePlugin:
        """Returns the plugin for this class."""
        if not self._model:
            return OpenSearchAzurePlugin(self.charm, relation_data=None)
        return OpenSearchAzurePlugin(self.charm, relation_data=self._model.credentials)

    @property
    @override
    def data(self) -> Dict[str, Any] | None:
        """Returns the data for the backup backend."""
        if not self._model:
            return None
        to_include = {"container", "base_path"}
        settings = {k: self._model.dict()[k] for k in to_include}
        return settings

    @override
    def get_service_status(self, response: dict[str, Any] | None) -> BackupServiceState:
        """Returns the response status in a Enum."""
        if (status := BackupManager.get_service_status(response)) == BackupServiceState.SUCCESS:
            return BackupServiceState.SUCCESS
        if (
            "container" in self.client.get_azure_storage_connection_info()
            and AZURE_REPOSITORY in response
            and "settings" in response[AZURE_REPOSITORY]
            and self.client.get_azure_storage_connection_info()["container"]
            == response[AZURE_REPOSITORY]["settings"]["container"]
        ):
            return BackupServiceState.REPO_NOT_CREATED_ALREADY_EXISTS
        return status


def backup(charm: "OpenSearchBaseCharm") -> OpenSearchBackupBase:
    """Implements the logic that returns the correct class according to the cluster type.

    This class is solely responsible for the creation of the correct azure client manager.

    If this cluster is an orchestrator or failover cluster, then return the OpenSearchBackup.
    Otherwise, return the OpenSearchNonOrchestratorBackup.

    There is also the condition where the deployment description does not exist yet. In this case,
    return the base class OpenSearchBackupBase. This class solely defers all backup related events
    until the deployment description is available and the actual S3/Azure object is allocated.
    """
    backup_base = OpenSearchBackupBase(charm)
    if not charm.opensearch_peer_cm.deployment_desc():
        # Temporary condition: we are waiting for CM to show up and define which type
        # of cluster are we. Once we have that defined, then we will process.
        # Additionally, we might not know yet which relation is active for the charm. If both
        # relations are active, let the actions fail and report it to the user.
        return backup_base
    elif charm.opensearch_peer_cm.deployment_desc().typ == DeploymentType.MAIN_ORCHESTRATOR:
        # Using the deployment_desc() method instead of is_provider()
        # In both cases: (1) small deployments or (2) large deployments where this cluster is the
        # main orchestrator, we want to instantiate the OpenSearchBackup class.
        if not backup_base.active_relation:
            return backup_base
        if backup_base.active_relation == S3_RELATION:
            return OpenSearchS3Backup(charm)
        if backup_base.active_relation == AZURE_RELATION:
            return OpenSearchAzureBackup(charm)
    return OpenSearchNonOrchestratorClusterBackup(charm)
