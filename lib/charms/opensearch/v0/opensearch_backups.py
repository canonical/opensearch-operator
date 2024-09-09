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

The OpenSearchBackup class listens to both relation changes from S3_RELATION and API calls
and responses. The OpenSearchBackupPlugin holds the configuration info. The classes together
manages the events related to backup/restore cycles.

The removal of backup only reverses step the API calls, to avoid accidentally deleting the
existing snapshots in the S3 repo.

The main class to interact with is the OpenSearchBackup. This class will observe the s3
relation and backup-related actions.

OpenSearchBackup finishes the config of the backup service once has been set/unset and a
restart has been applied. That means, in the case s3 has been related,
this class will apply the new configuration to opensearch.yml and keystore, then issue a
restart event. After the restart has been successful and if unit is leader: execute the
API calls to setup the backup.

A charm implementing this class must setup the following:

--> metadata.yaml
    ...

s3-credentials:
    interface: s3
    limit: 1


--> main charm file
    ...

from charms.opensearch.v0.opensearch_backups import OpenSearchBackup


class OpenSearchBaseCharm(CharmBase):
    def __init__(...):
        ...
        self.backup = OpenSearchBackupFactory(self)

###########################################################################################
#
# Large deployments
#
###########################################################################################

For developers, there is no meaningful difference between small and large deployments.
They both use the same backup_factory() to return the correct object for their case.

The large deployments expands the original concept of OpenSearchBackup to include other
juju applications that are not cluster_manager. This means a cluster may be a data-only or
even a failover cluster-manager and still interacts with s3-integrator at a certain level.

The baseline is that every unit in the cluster must import the S3 credentials. The main
orchestrator will share these credentials via the peer-cluster relation. Failover and data
clusters will import that information from the peer-cluster relation.

To implement the points above without causing too much disruption to the existing code,
a factory pattern has been adopted, where the main charm receives a OpenSearchBackupBase
object that corresponds to its own case (cluster-manager, failover, data, etc).
"""

import json
import logging
from abc import abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.opensearch.v0.constants_charm import (
    OPENSEARCH_BACKUP_ID_FORMAT,
    S3_RELATION,
    BackupConfigureStart,
    BackupDeferRelBrokenAsInProgress,
    BackupInDisabling,
    BackupSetupFailed,
    BackupSetupStart,
    PeerClusterRelationName,
    PluginConfigError,
    RestoreInProgress,
    S3RelShouldNotExist,
)
from charms.opensearch.v0.constants_secrets import S3_CREDENTIALS
from charms.opensearch.v0.helper_cluster import ClusterState, IndexStateEnum
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.models import DeploymentType
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
    OpenSearchNotFullyReadyError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_keystore import OpenSearchKeystoreNotReadyYetError
from charms.opensearch.v0.opensearch_locking import OpenSearchNodeLock
from charms.opensearch.v0.opensearch_plugins import OpenSearchBackupPlugin, PluginState
from ops.charm import ActionEvent
from ops.framework import EventBase, Object
from ops.model import BlockedStatus, MaintenanceStatus, WaitingStatus
from overrides import override
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

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


INDICES_TO_EXCLUDE_AT_RESTORE = {
    ".opendistro_security",
    ".opensearch-observability",
    OpenSearchNodeLock.OPENSEARCH_INDEX,
}

REPO_NOT_CREATED_ERR = "repository type [s3] does not exist"
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
    RESPONSE_FAILED_NETWORK = "response failed: network error"
    REPO_NOT_CREATED = "repository not created"
    REPO_NOT_CREATED_ALREADY_EXISTS = "repo not created as it already exists"
    REPO_CREATION_ERR = "Failed creating repository"
    REPO_ERR_UNKNOWN = "Repository exception: unknown"
    REPO_MISSING = "repository is missing from request"
    REPO_S3_UNREACHABLE = "repository s3 is unreachable"
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


class OpenSearchBackupBase(Object):
    """Works as parent for all backup classes.

    This class does a smooth transition between orchestrator and non-orchestrator clusters.
    """

    def __init__(self, charm: "OpenSearchBaseCharm", relation_name: str = PeerClusterRelationName):
        """Initializes the opensearch backup base.

        This class will not hold a s3_client object, as it is not intended to really
        manage the relation besides waiting for the deployment description.
        """
        super().__init__(charm, relation_name)
        self.charm = charm

        # We can reuse the same method, as the plugin manager will apply configs accordingly.
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)
        self.framework.observe(self.charm.on.secret_remove, self._on_secret_changed)

        for event in [
            self.charm.on[S3_RELATION].relation_created,
            self.charm.on[S3_RELATION].relation_joined,
            self.charm.on[S3_RELATION].relation_changed,
            self.charm.on[S3_RELATION].relation_departed,
            self.charm.on[S3_RELATION].relation_broken,
        ]:
            self.framework.observe(event, self._on_s3_relation_event)
        for event in [
            self.charm.on.create_backup_action,
            self.charm.on.list_backups_action,
            self.charm.on.restore_action,
        ]:
            self.framework.observe(event, self._on_s3_relation_action)

    def _on_secret_changed(self, event: EventBase) -> None:
        """Clean secret from the plugin cache."""
        secret = event.secret
        secret.get_content()

        if not event.secret.label:
            logger.info("Secret %s has no label, ignoring it.", event.secret.id)
            return

        if S3_CREDENTIALS not in event.secret.label:
            logger.debug("Secret %s is not s3-credentials, ignoring it.", event.secret.id)
            return

        if not self.charm.secrets.get_object(Scope.APP, "s3-creds"):
            logger.warning("Secret %s found but missing s3-credentials set.", event.secret.id)
            return

        try:
            self._charm.plugin_manager.apply_config(
                OpenSearchBackupPlugin(
                    plugin_path=self.charm.opensearch.paths.plugins,
                    charm=self.charm,
                ),
            )
        except OpenSearchKeystoreNotReadyYetError:
            logger.info("Keystore not ready yet, retrying later.")
            event.defer()

    def _on_s3_relation_event(self, event: EventBase) -> None:
        """Defers the s3 relation events."""
        logger.info("Deployment description not yet available, deferring s3 relation event")
        event.defer()

    @abstractmethod
    def _on_s3_relation_broken(self, event: EventBase) -> None:
        """Defers the s3 relation broken events."""
        raise NotImplementedError

    def _on_s3_relation_action(self, event: EventBase) -> None:
        """No deployment description yet, fail any actions."""
        logger.info("Deployment description not yet available, failing actions.")
        event.fail("Failed: deployment description not yet available")

    def _request(self, *args, **kwargs) -> dict[str, Any] | None:
        """Returns the output of OpenSearchDistribution.request() or throws an error.

        Request method can return one of many: Union[Dict[str, any], List[any], int]
        and raise multiple types of errors.

        If int is returned, then throws an exception informing the HTTP request failed.
        If the request fails, returns the error text or None if only status code is found.

        Raises:
          - ValueError
        """
        if "retries" not in kwargs.keys():
            kwargs["retries"] = 6
        if "timeout" not in kwargs.keys():
            kwargs["timeout"] = 10
        # We are interested to see the entire response
        kwargs["resp_status_code"] = False
        try:
            result = self.charm.opensearch.request(*args, **kwargs)
        except OpenSearchHttpError as e:
            return e.response_body
        return result if isinstance(result, dict) else None

    def _is_restore_in_progress(self) -> bool:
        """Checks if the restore is currently in progress.

        Two options:
         1) no restore requested: return False
         2) check for each index shard: for all type=SNAPSHOT and stage=DONE, return False.
        """
        try:
            indices_status = self._request("GET", "/_recovery?human") or {}
        except OpenSearchHttpError:
            # Defaults to True if we have a failure, to avoid any actions due to
            # intermittent connection issues.
            logger.warning(
                "_is_restore_in_progress: failed to get indices status"
                " - assuming restore is in progress"
            )
            return True

        for info in indices_status.values():
            # Now, check the status of each shard
            for shard in info["shards"]:
                if shard["type"] == "SNAPSHOT" and shard["stage"] != "DONE":
                    return True
        return False

    def is_backup_in_progress(self) -> bool:
        """Returns True if backup is in progress, False otherwise.

        We filter the _query_backup_status() and seek for the following states:
        - SNAPSHOT_IN_PROGRESS
        """
        if self._query_backup_status() in [
            BackupServiceState.SNAPSHOT_IN_PROGRESS,
            BackupServiceState.RESPONSE_FAILED_NETWORK,
        ]:
            # We have a backup in progress or we cannot reach the API
            # taking the "safe path" of informing a backup is in progress
            return True
        return False

    def _query_backup_status(self, backup_id: Optional[str] = None) -> BackupServiceState:
        try:
            for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(5)):
                with attempt:
                    target = f"_snapshot/{S3_REPOSITORY}/"
                    target += f"{backup_id.lower()}" if backup_id else "_all"
                    output = self._request("GET", target)
                    logger.debug(f"Backup status: {output}")
        except RetryError as e:
            logger.error(f"_request failed with: {e}")
            return BackupServiceState.RESPONSE_FAILED_NETWORK
        return self.get_service_status(output)

    def get_service_status(  # noqa: C901
        self, response: dict[str, Any] | None
    ) -> BackupServiceState:
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

        type = None
        try:
            if "error" not in response:
                return BackupServiceState.SUCCESS
            if "root_cause" not in response:
                return BackupServiceState.REPO_ERR_UNKNOWN
            type = response["error"]["root_cause"][0]["type"]
            reason = response["error"]["root_cause"][0]["reason"]
            logger.warning(f"response contained error: {type} - {reason}")
        except KeyError as e:
            logger.exception(e)
            logger.error("response contained unknown error code")
            return BackupServiceState.RESPONSE_FAILED_NETWORK
        # Check if we error'ed b/c s3 repo is not configured, hence we are still
        # waiting for the plugin to be configured
        if type == "repository_exception" and REPO_NOT_CREATED_ERR in reason:
            return BackupServiceState.REPO_NOT_CREATED
        if type == "repository_exception" and REPO_CREATING_ERR in reason:
            return BackupServiceState.REPO_CREATION_ERR
        if type == "repository_exception":
            return BackupServiceState.REPO_ERR_UNKNOWN
        if type == "repository_missing_exception":
            return BackupServiceState.REPO_MISSING
        if type == "repository_verification_exception" and REPO_NOT_ACCESS_ERR in reason:
            return BackupServiceState.REPO_S3_UNREACHABLE
        if type == "illegal_argument_exception":
            return BackupServiceState.ILLEGAL_ARGUMENT
        if type == "snapshot_missing_exception":
            return BackupServiceState.SNAPSHOT_MISSING
        if type == "snapshot_restore_exception" and RESTORE_OPEN_INDEX_WITH_SAME_NAME in reason:
            return BackupServiceState.SNAPSHOT_RESTORE_ERROR_INDEX_NOT_CLOSED
        if type == "snapshot_restore_exception":
            return BackupServiceState.SNAPSHOT_RESTORE_ERROR
        if type:
            # There is an error but we could not precise which is
            return BackupServiceState.REPO_ERR_UNKNOWN
        return self.get_snapshot_status(response)

    def get_snapshot_status(self, response: Dict[str, Any] | None) -> BackupServiceState:
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

    def is_idle_or_not_set(self) -> bool:
        """Checks if the backup system is idle or not yet configured.

        "idle": configured but there are no backups nor restores in progress.
        "not_set": set by the children classes
        """
        return not (
            self.is_set() or self.is_backup_in_progress() or self._is_restore_in_progress()
        )


class OpenSearchNonOrchestratorClusterBackup(OpenSearchBackupBase):
    """Simpler implementation of backup relation for non-orchestrator clusters.

    In a nutshell, non-orchestrator clusters should receive the backup information via
    peer-cluster relation instead; and must fail any action or major s3-relation events.

    This class means we are sure this juju app is a non-orchestrator. In this case, we must
    manage the update status correctly if the user ever tries to relate the s3-credentials.
    """

    def __init__(self, charm: "OpenSearchBaseCharm", relation_name: str = PeerClusterRelationName):
        """Manager of OpenSearch backup relations."""
        super().__init__(charm, relation_name)
        self.framework.observe(
            self.charm.on[S3_RELATION].relation_broken, self._on_s3_relation_broken
        )

    @override
    def _on_s3_relation_event(self, event: EventBase) -> None:
        """Processes the non-orchestrator cluster events."""
        self.charm.status.set(BlockedStatus(S3RelShouldNotExist))
        logger.info("Non-orchestrator cluster, abandon s3 relation event")

    @override
    def _on_s3_relation_broken(self, event: EventBase) -> None:
        """Processes the non-orchestrator cluster events."""
        self.charm.status.clear(S3RelShouldNotExist)
        logger.info("Non-orchestrator cluster, abandon s3 relation event")


class OpenSearchBackup(OpenSearchBackupBase):
    """Implements backup relation and API management."""

    def __init__(self, charm: "OpenSearchBaseCharm", relation_name: str = S3_RELATION):
        """Manager of OpenSearch backup relations."""
        super().__init__(charm, relation_name)
        self.s3_client = S3Requirer(self.charm, relation_name)
        self.plugin = OpenSearchBackupPlugin(self.charm)

        # s3 relation handles the config options for s3 backups
        self.framework.observe(self.charm.on[S3_RELATION].relation_created, self._on_s3_created)
        self.framework.observe(
            self.charm.on[S3_RELATION].relation_broken, self._on_s3_relation_broken
        )
        self.framework.observe(
            self.s3_client.on.credentials_changed, self._on_s3_credentials_changed
        )
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_backup_action)

    @override
    def _on_secret_changed(self, event: EventBase) -> None:
        # This method is not needed anymore, as we already listen to credentials_changed event.
        pass

    @override
    def _on_s3_relation_event(self, event: EventBase) -> None:
        """Overrides the parent method to process the s3 relation events, as we use s3_client.

        We run the peer cluster orchestrator's refresh on every new s3 information.
        """
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    @override
    def _on_s3_relation_action(self, event: EventBase) -> None:
        """Just overloads the base method, as we process each action in this class."""
        pass

    @property
    def _plugin_status(self):
        return self.charm.plugin_manager.get_plugin_status(OpenSearchBackupPlugin)

    def _format_backup_list(self, backups: List[Tuple[Any]]) -> str:
        """Formats provided list of backups as a table."""
        output = ["{:<20s} | {:s}".format(" backup-id", "backup-status")]
        output.append("-" * len(output[0]))

        for backup_id, backup_status in backups:
            output.append("{:<20s} | {:s}".format(backup_id, backup_status))
        return "\n".join(output)

    def _generate_backup_list_output(self, backups: Dict[str, Any]) -> str:
        """Generates a list of backups in a formatted table.

        List contains successful and failed backups in order of ascending time.

        Raises:
            OpenSearchError: if the list of backups errors
        """
        backup_list = []
        for id, backup in backups.items():
            state = self.get_snapshot_status(backup["state"])
            backup_list.append((id, state.value))
        return self._format_backup_list(backup_list)

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Returns the list of available backups to the user."""
        backups = {}
        try:
            backups = self._list_backups()
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

    def _close_indices(self, indices: Set[str]) -> bool:
        """Close a list of indices and return their status."""
        if not indices:
            # The indices is empty, we do not need to check
            return True
        resp = self._request(
            "POST",
            f"{','.join(indices)}/_close",
            payload={
                "ignore_unavailable": "true",
            },
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

    def _close_indices_if_needed(self, backup_id: int) -> Set[str]:
        """Closes indices that will be restored.

        Returns a set of indices that were closed or raises an exception:
        - OpenSearchRestoreIndexClosingError if any of the indices could not be closed.

        Raises:
            OpenSearchHttpError
            OpenSearchRestoreIndexClosingError
        """
        backup_indices = self._list_backups().get(backup_id, {}).get("indices", {})
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

    def _restore(self, backup_id: int) -> Dict[str, Any]:
        """Runs the restore and processes the response."""
        backup_indices = self._list_backups().get(backup_id, {}).get("indices", {})
        output = self._request(
            "POST",
            f"_snapshot/{S3_REPOSITORY}/{backup_id.lower()}/_restore?wait_for_completion=true",
            payload={
                "indices": ",".join(
                    [f"-{idx}" for idx in INDICES_TO_EXCLUDE_AT_RESTORE & set(backup_indices)]
                ),
                "partial": False,  # It is the default value, but we want to avoid partial restores
            },
        )
        logger.debug(f"_restore: restore call returned {output}")
        if (
            self.get_service_status(output)
            == BackupServiceState.SNAPSHOT_RESTORE_ERROR_INDEX_NOT_CLOSED
        ):
            to_close = output["error"]["reason"].split("[")[2].split("]")[0]
            raise OpenSearchRestoreIndexClosingError(f"_restore: fails to close {to_close}")

        if "snapshot" not in output or "shards" not in output.get("snapshot"):
            raise OpenSearchRestoreCheckError(f"_restore: unexpected response {output}")

        return output["snapshot"]

    def is_idle_or_not_set(self) -> bool:
        """Checks if the backup system is idle or not yet configured.

        "idle": configured but there are no backups nor restores in progress.
        "not_set": the `get_service_status` returns REPO_NOT_CREATED or REPO_MISSING.

        Raises:
            OpenSearchHttpError: cluster is unreachable
        """
        output = self._request("GET", f"_snapshot/{S3_REPOSITORY}")
        return self.get_service_status(output) in [
            BackupServiceState.REPO_NOT_CREATED,
            BackupServiceState.REPO_MISSING,
        ] or not (self.is_backup_in_progress() or self._is_restore_in_progress())

    def _is_restore_complete(self) -> bool:
        """Checks if the restore is finished.

        Essentially, check for each index shard: for all type=SNAPSHOT and stage=DONE, return True.
        """
        indices_status = self._request("GET", "/_recovery?human")
        if not indices_status:
            # No restore has happened. Raise an exception
            raise OpenSearchRestoreCheckError("_is_restore_complete: failed to get indices status")
        return not self._is_restore_in_progress()

    def _is_backup_available_for_restore(self, backup_id: int) -> bool:
        """Checks if the backup_id exists and is ready for a restore."""
        backups = self._list_backups()
        try:
            return (
                backup_id in backups.keys()
                and self.get_snapshot_status(backups[backup_id]["state"])
                == BackupServiceState.SUCCESS
            )
        except OpenSearchListBackupError:
            return False

    def _on_restore_backup_action(self, event: ActionEvent) -> None:  # noqa #C901
        """Restores a backup to the current cluster."""
        if self.charm.upgrade_in_progress:
            event.fail("Restore not supported while upgrade in-progress")
            return
        if not self._can_unit_perform_backup(event):
            event.fail("Failed: backup service is not configured yet")
            return
        try:
            if not self._is_restore_complete():
                event.fail("Failed: previous restore is still in progress")
                return
        except OpenSearchRestoreCheckError:
            event.fail("Failed: error connecting to the cluster")
            return
        # Now, validate the backup is working
        backup_id = event.params.get("backup-id")
        if not self._is_backup_available_for_restore(backup_id):
            event.fail(f"Failed: no backup-id {backup_id}")
            return

        self.charm.status.set(MaintenanceStatus(RestoreInProgress))

        # Restore will try to close indices if there is a matching name.
        # The goal is to leave the cluster in a running state, even if the restore fails.
        # In case of failure, then restore action must return a list of closed indices
        closed_idx = set()
        try:
            closed_idx = self._close_indices_if_needed(backup_id)
            output = self._restore(backup_id)
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
                "Restore is complete" if self._is_restore_complete() else "Restore in progress..."
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
        if not self._can_unit_perform_backup(event):
            event.fail("Failed: backup service is not configured or busy")
            return

        new_backup_id = datetime.now().strftime(OPENSEARCH_BACKUP_ID_FORMAT)
        try:
            logger.debug(
                f"Create backup action request id {new_backup_id} response is:"
                + self.get_service_status(
                    self._request(
                        "PUT",
                        f"_snapshot/{S3_REPOSITORY}/{new_backup_id.lower()}?wait_for_completion=false",
                        payload={
                            "indices": "*",  # Take all indices
                            "partial": False,  # It is the default value, but we want to avoid partial backups
                        },
                    )
                )
            )

            logger.info(f"Backup request submitted with backup-id {new_backup_id}")
        except (
            OpenSearchHttpError,
            OpenSearchListBackupError,
        ) as e:
            event.fail(f"Failed with exception: {e}")
            return
        event.set_results({"backup-id": new_backup_id, "status": "Backup is running."})

    def _can_unit_perform_backup(self, _: ActionEvent) -> bool:
        """Checks if the actions run from this unit can be executed or not.

        If not, then register the reason as a failure in the event and returns False.
        Returns True otherwise.

        This method does not check if the unit is a leader, as list backups action does
        not demand it.
        """
        # First, validate the plugin is present and correctly configured.
        if self._plugin_status != PluginState.ENABLED:
            logger.warning(
                f"Failed: plugin is not ready yet, current status is {self._plugin_status}"
            )
            return False

        # Then, check the repo status
        status = self._check_repo_status()
        if status != BackupServiceState.SUCCESS:
            logger.warning(f"Failed: repo status is {status}")
            return False
        return not self.is_backup_in_progress()

    def _list_backups(self) -> Dict[int, str]:
        """Returns a mapping of snapshot ids / state."""
        # Using the original request method, as we want to raise an http exception if we
        # cannot get the snapshot list.
        response = self.charm.opensearch.request("GET", f"_snapshot/{S3_REPOSITORY}/_all")
        return {
            snapshot["snapshot"].upper(): {
                "state": snapshot["state"],
                "indices": snapshot.get("indices", []),
            }
            for snapshot in response.get("snapshots", [])
        }

    def _on_s3_credentials_changed(self, event: EventBase) -> None:  # noqa: C901
        """Calls the plugin manager config handler.

        This method will iterate over the s3 relation and check:
        1) Is S3 fully configured? If not, we can abandon this event
        2) Try to enable the plugin
        3) If the plugin is not enabled, then defer the event
        4) Send the API calls to setup the backup service
        """
        if not self.plugin.is_set():
            # Always check if a relation actually exists and if options are available
            # in this case, seems one of the conditions above is not yet present
            # abandon this restart event, as it will be called later once s3 configuration
            # is correctly set
            return

        if self.plugin.data.tls_ca_chain is not None:
            raise NotImplementedError

        self.charm.status.set(MaintenanceStatus(BackupSetupStart))

        try:
            if not self.charm.plugin_manager.is_ready_for_api():
                raise OpenSearchNotFullyReadyError()
            self.charm.plugin_manager.apply_config(self.plugin.config())
        except (OpenSearchKeystoreNotReadyYetError, OpenSearchNotFullyReadyError):
            logger.warning("s3-changed: cluster not ready yet")
            event.defer()
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
            return

        # Leader configures this plugin
        try:
            self.apply_api_config_if_needed()
        except OpenSearchBackupError:
            event.defer()
            return
        self.charm.status.clear(PluginConfigError)
        self.charm.status.clear(BackupSetupStart)

    def apply_api_config_if_needed(self) -> None:
        """Runs the post restart routine and API calls needed to setup/disable backup.

        This method should be called by the charm in its restart callback resolution.
        """
        # Backup relation has been recently made available with all the parameters needed.
        # Steps:
        #     (1) set up as maintenance;
        self.charm.status.set(MaintenanceStatus(BackupConfigureStart))
        #     (2) run the request; and
        state = self._register_snapshot_repo()
        #     (3) based on the response, set the message status
        if state != BackupServiceState.SUCCESS:
            logger.error(f"Failed to setup backup service with state {state}")
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(BackupSetupFailed), app=True)
            self.charm.status.clear(BackupConfigureStart)
            raise OpenSearchBackupError()
        if self.charm.unit.is_leader():
            self.charm.status.clear(BackupSetupFailed, app=True)
        self.charm.status.clear(BackupConfigureStart)

    def _on_s3_created(self, _):
        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )

    @override
    def _on_s3_relation_broken(self, event: EventBase) -> None:  # noqa: C901
        """Processes the broken s3 relation.

        It runs the reverse process of on_s3_change:
        1) Check if the cluster is currently taking a snapshot, if yes, set status as blocked
           and defer this event.
        2) If leader, run API calls to signal disable is needed
        """
        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )

        if (
            self.charm.model.get_relation(S3_RELATION)
            and self.charm.model.get_relation(S3_RELATION).units
        ):
            event.defer()
            return

        self.charm.status.set(MaintenanceStatus(BackupInDisabling))
        snapshot_status = self._check_snapshot_status()
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
        if self.charm.unit.is_leader():
            # 2) Run the API calls
            self._execute_s3_broken_calls()

        try:
            if self.charm.plugin_manager.status(self.plugin) == PluginState.ENABLED:
                self.charm.plugin_manager.apply_config(self.plugin.disable())
        except OpenSearchKeystoreNotReadyYetError:
            logger.warning("s3-changed: keystore not ready yet")
            event.defer()
            return
        except OpenSearchError as e:
            self.charm.status.set(BlockedStatus(PluginConfigError))
            # There was an unexpected error, log it and block the unit
            logger.error(e)
            event.defer()
            return

        # Let's reset the current plugin
        self.plugin.data = {}

        self.charm.status.clear(BackupInDisabling)
        self.charm.status.clear(PluginConfigError)

    def _execute_s3_broken_calls(self):
        """Executes the s3 broken API calls."""
        return  # do not execute anything as we intend to keep the backups untouched

    def _check_repo_status(self) -> BackupServiceState:
        try:
            return self.get_service_status(self._request("GET", f"_snapshot/{S3_REPOSITORY}"))
        except OpenSearchHttpError:
            return BackupServiceState.RESPONSE_FAILED_NETWORK

    def _check_snapshot_status(self) -> BackupServiceState:
        try:
            return self.get_snapshot_status(self._request("GET", "/_snapshot/_status"))
        except OpenSearchHttpError:
            return BackupServiceState.RESPONSE_FAILED_NETWORK

    def _get_endpoint_protocol(self, endpoint: str) -> str:
        """Returns the protocol based on the endpoint."""
        if endpoint.startswith("http://"):
            return "http"
        if endpoint.startswith("https://"):
            return "https"
        return "https"

    def _register_snapshot_repo(self) -> BackupServiceState:
        """Registers the snapshot repo in the cluster."""
        return self.get_service_status(
            self._request(
                "PUT",
                f"_snapshot/{S3_REPOSITORY}",
                payload={
                    "type": "s3",
                    "settings": self.plugin.data.dict(exclude={"tls_ca_chain", "credentials"}),
                },
            )
        )

    def get_service_status(  # noqa: C901
        self, response: dict[str, Any] | None
    ) -> BackupServiceState:
        """Returns the response status in a Enum."""
        if (status := super().get_service_status(response)) == BackupServiceState.SUCCESS:
            return BackupServiceState.SUCCESS
        if (
            "bucket" in self.s3_client.get_s3_connection_info()
            and S3_REPOSITORY in response
            and "settings" in response[S3_REPOSITORY]
            and self.s3_client.get_s3_connection_info()["bucket"]
            == response[S3_REPOSITORY]["settings"]["bucket"]
        ):
            return BackupServiceState.REPO_NOT_CREATED_ALREADY_EXISTS
        return status


def backup(charm: "OpenSearchBaseCharm") -> OpenSearchBackupBase:
    """Implements the logic that returns the correct class according to the cluster type.

    This class is solely responsible for the creation of the correct S3 client manager.

    If this cluster is an orchestrator or failover cluster, then return the OpenSearchBackup.
    Otherwise, return the OpenSearchNonOrchestratorBackup.

    There is also the condition where the deployment description does not exist yet. In this
    case, return the base class OpenSearchBackupBase. This class solely defers all s3-related
    events until the deployment description is available and the actual S3 object is allocated.
    """
    if not charm.opensearch_peer_cm.deployment_desc():
        # Temporary condition: we are waiting for CM to show up and define which type
        # of cluster are we. Once we have that defined, then we will process.
        return OpenSearchBackupBase(charm)
    elif charm.opensearch_peer_cm.deployment_desc().typ == DeploymentType.MAIN_ORCHESTRATOR:
        # Using the deployment_desc() method instead of is_provider()
        # In both cases: (1) small deployments or (2) large deployments where this cluster is the
        # main orchestrator, we want to instantiate the OpenSearchBackup class.
        return OpenSearchBackup(charm)
    return OpenSearchNonOrchestratorClusterBackup(charm)
