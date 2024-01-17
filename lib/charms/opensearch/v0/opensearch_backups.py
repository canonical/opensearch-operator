# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Backup.

This file holds the implementation of the OpenSearchBackup, OpenSearchBackupPlugin classes
as well as the configuration and state enum.

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
        self.backup = OpenSearchBackup(self)
"""

import json
import logging
import math
from typing import Any, Dict, List, Set, Tuple

import requests
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.helper_cluster import ClusterState
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchBackupPlugin,
    OpenSearchPluginEventScope,
    OpenSearchPluginRelationClusterNotReadyError,
    PluginState,
)
from ops.charm import ActionEvent
from ops.framework import EventBase, Object
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

# The unique Charmhub library identifier, never change it
LIBID = "d301deee4d2c4c1b8e30cd3df8034be2"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


# OpenSearch Backups
S3_RELATION = "s3-credentials"
S3_REPOSITORY = "s3-repository"


S3_REPO_BASE_PATH = "/"

INDICES_TO_EXCLUDE_AT_RESTORE = {
    ".opendistro_security",
    ".opensearch-observability",
    ".opensearch-sap-log-types-config",
    ".opensearch-sap-pre-packaged-rules-config",
}

REPO_NOT_CREATED_ERR = "repository type [s3] does not exist"
REPO_NOT_ACCESS_ERR = f"[{S3_REPOSITORY}] path [{S3_REPO_BASE_PATH}] is not accessible"
REPO_CREATING_ERR = "Could not determine repository generation from root blobs"
RESTORE_OPEN_INDEX_WITH_SAME_NAME = "because an open index with same name already exists"


class OpenSearchBackupError(OpenSearchError):
    """Exception thrown when an opensearch backup-related action fails."""


class OpenSearchRestoreError(OpenSearchError):
    """Exception thrown when an opensearch restore-related action fails."""


class OpenSearchRestoreSingleUnitNotAsyncError(OpenSearchRestoreError):
    """Exception thrown when running a single unit and async restore is requested."""


class OpenSearchListBackupError(OpenSearchBackupError):
    """Exception thrown when internal list backups call fails."""


class OpenSearchRestoreCheckError(OpenSearchRestoreError):
    """Exception thrown when restore status check errors."""


class OpenSearchRestoreFailedClosingIdxError(OpenSearchRestoreError):
    """Exception thrown when restore fails to close indices."""


class OpenSearchRestoreMismatchBetweenIdxAndSnapshotError(OpenSearchRestoreError):
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


class OpenSearchBackup(Object):
    """Implements backup relation and API management."""

    def __init__(self, charm: Object):
        """Manager of OpenSearch backup relations."""
        super().__init__(charm, S3_RELATION)
        self.charm = charm
        # s3 relation handles the config options for s3 backups
        self.s3_client = S3Requirer(self.charm, S3_RELATION)
        self.framework.observe(self.charm.on[S3_RELATION].relation_broken, self._on_s3_broken)
        self.framework.observe(
            self.s3_client.on.credentials_changed, self._on_s3_credentials_changed
        )
        self.framework.observe(self.charm.on.update_status, self._on_update_status)
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_backup_action)
        self.framework.observe(
            self.charm.on.check_restore_status_action, self._on_check_restore_status_action
        )

    def _on_update_status(self, _):
        """Checks if the backup and/or restores are finished."""
        status = self._check_repo_status()
        if status == BackupServiceState.SUCCESS:
            # There is a repo setup, check if we have any backup/restore registered in the
            # peer relation's app databag
            logger.info(f"Checking if backup in progress: {self.is_backup_in_progress()}")
            logger.info(f"Checking if restore in progress: {self._check_if_restore_finished()}")

    @property
    def _plugin_status(self):
        return self.charm.plugin_manager.get_plugin_status(OpenSearchBackupPlugin)

    def _format_backup_list(self, backup_list: List[Tuple[Any]]) -> str:
        """Formats provided list of backups as a table."""
        backups = ["{:<10s} | {:s}".format(" backup-id ", "backup-status")]
        backups.append("-" * len(backups[0]))

        for backup_id, backup_status in backup_list:
            tab = " " * math.floor((10 - len(str(backup_id))) / 2)
            backups.append("{:<10s} | {:s}".format(f"{tab}{backup_id}", backup_status))
        return "\n".join(backups)

    def _generate_backup_list_output(self, backups: Dict[str, Any]) -> str:
        """Generates a list of backups in a formatted table.

        List contains successful and failed backups in order of ascending time.

        Raises:
            OpenSearchError: if the list of backups errors
        """
        backup_list = []
        for id, backup in backups.items():
            state = self.get_snapshot_status(backup["state"])
            backup_list.append(
                (
                    id,
                    str(state) if state != BackupServiceState.SUCCESS else "finished",
                )
            )
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
            event.set_results({"backups": (json.dumps(backups)).replace("_", "-")})
        elif event.params.get("output").lower() == "table":
            event.set_results({"backups": self._generate_backup_list_output(backups)})
        else:
            event.fail("Failed: invalid output format, must be either json or table")

    def _close_indices_if_needed(self, backup_indices: List[str]) -> Set[str]:
        """Closes indices that will be restored.

        Returns a set of indices that were closed or raises an exception:
        - OpenSearchRestoreFailedClosingIdxError if any of the indices could not be closed.
        """
        closed_idx = set()
        try:
            for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(wait=30)):
                with attempt:
                    to_close = [
                        index
                        for index, state in ClusterState.indices(self.charm.opensearch).items()
                        if (
                            index in backup_indices
                            and state["status"] != "close"
                            and index not in INDICES_TO_EXCLUDE_AT_RESTORE
                        )
                    ]
                    # Try closing each index
                    for index in to_close:
                        # Try closing the index
                        o = self._request("POST", f"{index}/_close")
                        logger.debug(
                            f"_close_indices_if_needed: request closing {index} returned {o}"
                        )
                        assert o.get("acknowledged", False)
                        assert index in o.get("indices", {})
                        closed_idx.add(index)
        except RetryError:
            raise OpenSearchRestoreFailedClosingIdxError(
                "_close_indices_if_needed: fail all retries"
            )
        return closed_idx

    def _issue_restore_request(
        self, backup_id: int, backup_indices: List[str], wait_for_completion: bool = False
    ) -> Dict[str, Any]:
        """Runs the restore and processes the response according to wait_for_completion flag."""
        # backup_indices = self._list_backups()[backup_id]["indices"]
        output = self._request(
            "POST",
            f"_snapshot/{S3_REPOSITORY}/{backup_id}/_restore?wait_for_completion={str(wait_for_completion).lower()}",
            payload={
                "indices": ",".join(
                    [f"-{idx}" for idx in INDICES_TO_EXCLUDE_AT_RESTORE & set(backup_indices)]
                ),
                "ignore_unavailable": False,
                "include_global_state": False,
                "include_aliases": True,
                "partial": False,
            },
        )
        logger.debug(f"_issue_restore_request: restore call returned {output}")
        if (
            self.get_service_status(output)
            == BackupServiceState.SNAPSHOT_RESTORE_ERROR_INDEX_NOT_CLOSED
        ):
            to_close = output["error"]["reason"].split("[")[2].split("]")[0]
            raise OpenSearchRestoreFailedClosingIdxError(
                f"_issue_restore_request: fails to close {to_close}"
            )
        return output

    def _check_if_restore_finished(self) -> bool:  # noqa: C901
        rel = self.model.get_relation(PeerRelationName)
        if not rel:
            # Running on a single unit, wait_for_completion=false not supported
            return True
        if not rel.data[self.charm.app].get("restore_in_progress"):
            # Dealing with an empty set
            return True
        closed_idx = set(rel.data[self.charm.app].get("restore_in_progress", "").split(",")).copy()
        # Check if all indices are open again
        try:
            indices_status = self._request(
                "GET",
                "/_recovery?human",
            )
        except (ValueError, OpenSearchHttpError, requests.HTTPError) as e:
            raise OpenSearchRestoreCheckError(f"Failed GET to /_recovery with : {e}")
        if isinstance(indices_status, str):
            indices_status = json.loads(indices_status)
        elif isinstance(indices_status, list) or isinstance(indices_status, set):
            raise ValueError("Unexpected output from /_recovery: type list received")

        indices_not_found = closed_idx.copy()
        for idx, info in indices_status.items():
            if idx in closed_idx:
                indices_not_found.discard(idx)
            else:
                continue
            # Now, check the status of each shard
            done = True
            for shard in info["shards"]:
                if shard["type"] != "SNAPSHOT":
                    continue
                if shard["stage"] != "DONE":
                    done = False
                    break
            if done:
                closed_idx.discard(idx)

        if indices_not_found:
            raise OpenSearchRestoreMismatchBetweenIdxAndSnapshotError(
                f"Failed to find indices {indices_not_found} in /_recovery"
            )
        if (
            not closed_idx
            and self.charm.unit.is_leader()
            and "restore_in_progress" in rel.data[self.charm.app]
        ):
            del rel.data[self.charm.app]["restore_in_progress"]
            return True
        return False

    def _on_check_restore_status_action(self, event: ActionEvent) -> None:
        """Checks the status of indices that have been recovered from snapshot."""
        try:
            if self._check_if_restore_finished():
                event.set_results({"state": "successful restore!"})
                return
            event.set_results({"state": "restore in progress..."})
        except Exception as e:
            event.fail(f"Failed: {e}")

    def _backup_is_available_for_restore(self, backup_id: int) -> bool:
        """Checks if the backup_id exists and is ready for a restore."""
        backups = self._list_backups()
        try:
            return (
                backup_id in backups.keys()
                and self.get_snapshot_status(backups[backup_id]["state"])
                != BackupServiceState.SUCCESS
            )
        except OpenSearchListBackupError:
            return False

    def _on_restore_backup_action(self, event: ActionEvent) -> None:  # noqa: C901
        """Restores a backup to the current cluster."""
        if not self._can_unit_perform_backup(event):
            event.fail("Failed: backup service is not configured yet")
            return

        if not self._check_if_restore_finished():
            event.fail("Failed: previous restore is still in progress")
            return
        # Now, validate the backup is working
        backup_id = str(event.params.get("backup-id"))
        if self._backup_is_available_for_restore(backup_id):
            event.fail(f"Failed: no backup-id {backup_id}")
            return

        # Restore will try to close indices if there is a matching name.
        # The goal is to leave the cluster in a running state, even if the restore fails.
        # In case of failure, then restore action must return a list of closed indices
        closed_idx = set()
        try:
            closed_idx = self._close_indices_if_needed()
            output = self._issue_restore_request(
                backup_id, event.params.get("wait-for-completion", False)
            )
            logger.debug(f"Restore action: received response: {output}")
            logger.info(f"Restore action succeeded for backup_id {backup_id}")
        except OpenSearchRestoreFailedClosingIdxError as e:
            event.fail(f"Failed: {e}")
            return

        # Post execution checks
        # Was the call successful?
        if self.get_service_status(output) != BackupServiceState.SUCCESS:
            status = str(self.get_service_status(output))
            event.fail(f"Failed with: {status}, closed indices: {closed_idx}")
            return
        # Finally, if status returns success, ensure all indices have been updated
        # otherwise, raise an assert error and retry
        if event.params.get("wait-for-completion", False):
            # We are waiting for restore to complete, then we need to check the status
            shards = output.get("snapshot", {}).get("shards", {})
            assert shards.get("successful", -1) == shards.get("total", 0)
        elif output.get("accepted", False):
            rel = self.model.get_relation(PeerRelationName)
            if rel and closed_idx:
                rel.data[self.charm.app]["restore_in_progress"] = ",".join(closed_idx)
            else:
                event.fail("Failed: no relation available to store the restore status")
                return
        event.set_results({"state": "successful restore!", "closed-indices": str(closed_idx)})

    def _on_create_backup_action(self, event: ActionEvent) -> None:  # noqa: C901
        """Creates a backup from the current cluster."""
        if not self._can_unit_perform_backup(event):
            event.fail("Failed: backup service is not configured yet")
            return

        new_backup_id = None
        wait_for_completion = event.params.get("wait-for-completion", False)
        rel = self.model.get_relation(PeerRelationName)
        if not rel and not wait_for_completion:
            event.fail(
                "Failed: single unit backup with wait_for_completion=false is not supported!"
            )
            return

        try:
            # Check if any backup is not running already, or RetryError happens
            if self.is_backup_in_progress():
                event.fail("Backup still in progress: aborting this request...")
                return
            # Increment by 1 the latest snapshot_id (set to 0 if no snapshot was previously made)
            new_backup_id = int(max(self._list_backups().keys() or [0])) + 1
            logger.debug(
                f"Create backup action request id {new_backup_id} response is:"
                + self.get_service_status(
                    self._request(
                        "PUT",
                        f"_snapshot/{S3_REPOSITORY}/{new_backup_id}?wait_for_completion={str(wait_for_completion).lower()}",
                        payload={
                            "indices": "*",
                            "ignore_unavailable": False,
                            "include_global_state": True,
                            "partial": False,
                        },
                    )
                )
            )

            logger.info(f"Backup request submitted with backup-id {new_backup_id}")

            if wait_for_completion:
                # Wait for the backup to finish
                for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(wait=30)):
                    with attempt:
                        if not self.is_backup_in_progress(new_backup_id):
                            break
                        logger.debug("Backup in progress, waiting for completion...")
                logger.info(f"Backup completed with backup-id {new_backup_id}")

        except RetryError as e:
            if wait_for_completion and self.is_backup_in_progress():
                event.fail(f"Timed out while waiting for: backup id {new_backup_id}")
                return
            if wait_for_completion:
                event.fail(f"Failed while waiting with error {e}")
                return
        except (
            ValueError,
            OpenSearchHttpError,
            requests.HTTPError,
            OpenSearchListBackupError,
        ) as e:
            event.fail(f"Failed with exception: {e}")
            return
        if wait_for_completion:
            event.set_results({"backup-id": new_backup_id, "status": "Backup completed."})
            return
        rel.data[self.charm.app]["backup_in_progress"] = str(new_backup_id)
        event.set_results({"backup-id": new_backup_id, "status": "Backup is running."})

    def _can_unit_perform_backup(self, event: ActionEvent) -> bool:
        """Checks if the actions run from this unit can be executed or not.

        If not, then register the reason as a failure in the event and returns False.
        Returns True otherwise.

        This method does not check if the unit is a leader, as list backups action does
        not demand it.
        """
        # First, validate the plugin is present and correctly configured.
        if self._plugin_status != PluginState.ENABLED:
            event.fail(f"Failed: plugin is not ready yet, current status is {self._plugin_status}")
            return False

        # Then, check the repo status
        status = self._check_repo_status()
        if status != BackupServiceState.SUCCESS:
            event.fail(f"Failed: repo status is {status}")
            return False
        return True

    def _list_backups(self) -> Dict[int, str]:
        """Returns a mapping of snapshot ids / state."""
        response = self._request("GET", f"_snapshot/{S3_REPOSITORY}/_all")
        return {
            snapshot["snapshot"]: {
                "state": snapshot["state"],
                "indices": snapshot.get("indices", []),
            }
            for snapshot in response.get("snapshots", [])
        }

    def is_backup_in_progress(self, backup_id=None) -> bool:
        """Returns True if backup is in progress, False otherwise.

        First, check if we have a marker of a running backup. If yes, then we check for both the
        saved backup_id in peer relation AND backup_id, if provided. If neither are in progress,
        return False and clean up the marker from the relation.
        """
        rel = self.model.get_relation(PeerRelationName)
        if rel:
            # If relation is present, then check the peer relation data
            peer_relation_backup_id = rel.data[self.charm.app].get("backup_in_progress", None)
            if peer_relation_backup_id and self._query_backup_status(backup_id) in [
                BackupServiceState.SNAPSHOT_IN_PROGRESS
            ]:
                # We have a backup in progress
                return True
            else:
                # Clean up status
                if (
                    self.charm.unit.is_leader()
                    and "backup_in_progress" in rel.data[self.charm.app]
                ):
                    del rel.data[self.charm.app]["backup_in_progress"]
        backup_id_in_progress = self._query_backup_status(backup_id) in [
            BackupServiceState.SNAPSHOT_IN_PROGRESS,
        ]
        if backup_id_in_progress:
            # We have a backup in progress
            if (
                peer_relation_backup_id
                and peer_relation_backup_id != backup_id_in_progress
                and self.charm.unit.is_leader()
            ):
                # We need to update our peer relation as the IDs were different
                rel.data[self.charm.app]["backup_in_progress"] = str(backup_id_in_progress)
            return True
        return False

    def _query_backup_status(self, backup_id=None) -> BackupServiceState:
        target = f"_snapshot/{S3_REPOSITORY}/"
        target += f"{backup_id}" if backup_id else "_all"
        output = self._request("GET", target)
        logger.debug(f"Backup status: {output}")
        return self.get_service_status(output)

    def _on_s3_credentials_changed(self, event: EventBase) -> None:
        """Calls the plugin manager config handler.

        This method will iterate over the s3 relation and check:
        1) Is S3 fully configured? If not, we can abandon this event
        2) Try to enable the plugin
        3) If the plugin is not enabled, then defer the event
        4) Send the API calls to setup the backup service
        """
        if not self.can_use_s3_repository():
            # Always check if a relation actually exists and if options are available
            # in this case, seems one of the conditions above is not yet present
            # abandon this restart event, as it will be called later once s3 configuration
            # is correctly set
            return

        if self.s3_client.get_s3_connection_info().get("tls-ca-chain"):
            raise NotImplementedError

        self.charm.status.set(WaitingStatus("Setting up backup service"))

        try:
            plugin = self.charm.plugin_manager.get_plugin(OpenSearchBackupPlugin)
            if self.charm.plugin_manager.status(plugin) == PluginState.ENABLED:
                self.charm.plugin_manager.disable(plugin)
            self.charm.plugin_manager.configure(plugin)
        except OpenSearchError as e:
            if isinstance(e, OpenSearchPluginRelationClusterNotReadyError):
                self.charm.status.set(WaitingStatus("s3-changed: cluster not ready yet"))
            else:
                self.charm.status.set(
                    BlockedStatus("Unexpected error during plugin configuration, check the logs")
                )
                # There was an unexpected error, log it and block the unit
                logger.error(e)
            event.defer()
            return

        if self._plugin_status not in [
            PluginState.ENABLED,
            PluginState.WAITING_FOR_UPGRADE,
        ]:
            self.charm.status.set(WaitingStatus(f"Plugin in state {self._plugin_status}"))
            event.defer()
            return

        if not self.charm.unit.is_leader():
            # Plugin is configured locally for this unit. Now the leader proceed.
            self.charm.status.set(ActiveStatus())
            return
        self.apply_api_config_if_needed()

    def apply_api_config_if_needed(self) -> None:
        """Runs the post restart routine and API calls needed to setup/disable backup.

        This method should be called by the charm in its restart callback resolution.
        """
        # Backup relation has been recently made available with all the parameters needed.
        # Steps:
        #     (1) set up as maintenance;
        self.charm.status.set(MaintenanceStatus("Configuring backup service..."))
        #     (2) run the request; and
        state = self._register_snapshot_repo()
        #     (3) based on the response, set the message status
        if state != BackupServiceState.SUCCESS:
            self.charm.status.set(BlockedStatus(f"Backup setup failed with {state}"))
        else:
            self.charm.status.set(ActiveStatus())

    def _on_s3_broken(self, event: EventBase) -> None:  # noqa: C901
        """Processes the broken s3 relation.

        It runs the reverse process of on_s3_change:
        1) Check if the cluster is currently taking a snapshot, if yes, set status as blocked
           and defer this event.
        2) If leader, run API calls to signal disable is needed
        """
        if (
            self.charm.model.get_relation(S3_RELATION)
            and self.charm.model.get_relation(S3_RELATION).units
        ):
            # There are still members in the relation, defer until it is finished
            # Make a relation-change in the peer relation, so it triggers this unit back
            counter = self.charm.peers_data.get(Scope.UNIT, "s3_broken")
            if counter:
                self.charm.peers_data.put(Scope.UNIT, "s3_broken", counter + 1)
            else:
                self.charm.peers_data.put(Scope.UNIT, "s3_broken", 1)
            event.defer()
            return

        # Second part of this work-around
        if self.charm.peers_data.get(Scope.UNIT, "s3_broken"):
            # Now, we can delete it
            self.charm.peers_data.delete(Scope.UNIT, "s3_broken")

        self.charm.status.set(MaintenanceStatus("Disabling backup service..."))
        snapshot_status = self._check_snapshot_status()
        if snapshot_status in [
            BackupServiceState.SNAPSHOT_IN_PROGRESS,
        ]:
            # 1) snapshot is either in progress or partially taken: block and defer this event
            self.charm.status.set(
                MaintenanceStatus(
                    f"Disabling backup postponed until backup in progress: {snapshot_status}"
                )
            )
            event.defer()
            return
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
            self.charm.plugin_manager.set_event_scope(
                OpenSearchPluginEventScope.RELATION_BROKEN_EVENT
            )
            plugin = self.charm.plugin_manager.get_plugin(OpenSearchBackupPlugin)
            self.charm.plugin_manager._disable_if_needed(plugin)
        except OpenSearchError as e:
            if isinstance(e, OpenSearchPluginRelationClusterNotReadyError):
                self.charm.status.set(WaitingStatus("s3-broken event: cluster not ready yet"))
            else:
                self.charm.status.set(
                    BlockedStatus("Unexpected error during plugin configuration, check the logs")
                )
                # There was an unexpected error, log it and block the unit
                logger.error(e)
            self.charm.plugin_manager.reset_event_scope()
            event.defer()
            return
        # we need to do this task, so we will ask for an exception from lint
        except:  # noqa: E722
            self.charm.plugin_manager.reset_event_scope()
            return
        self.charm.plugin_manager.reset_event_scope()
        self.charm.status.set(ActiveStatus())

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
        info = self.s3_client.get_s3_connection_info()
        extra_settings = {}
        if info.get("region"):
            extra_settings["region"] = info.get("region")
        if info.get("storage-class"):
            extra_settings["storage_class"] = info.get("storage-class")

        return self.get_service_status(
            self._request(
                "PUT",
                f"_snapshot/{S3_REPOSITORY}",
                payload={
                    "type": "s3",
                    "settings": {
                        "endpoint": info.get("endpoint"),
                        "protocol": self._get_endpoint_protocol(info.get("endpoint")),
                        "bucket": info["bucket"],
                        "base_path": info.get("path", S3_REPO_BASE_PATH),
                        **extra_settings,
                    },
                },
            )
        )

    def can_use_s3_repository(self) -> bool:
        """Checks if relation is set and all configs needed are present.

        The get_s3_connection_info() checks if the relation is present, and if yes,
        returns the data in it.

        This method will go over the output and generate a list of missing parameters
        that are manadatory to have be present. An empty list means everything is present.
        """
        missing_s3_configs = [
            config
            for config in ["bucket", "endpoint", "access-key", "secret-key"]
            if config not in self.s3_client.get_s3_connection_info()
        ]
        if missing_s3_configs:
            logger.warn(f"Missing following configs {missing_s3_configs} in s3 relation")
            rel = self.charm.model.get_relation(S3_RELATION)
            if rel and rel.units:
                # Now, there is genuine interest in configuring S3 correctly,
                # hence we generate the status
                self.charm.status.set(
                    WaitingStatus(
                        f"Waiting for s3 relation to be fully configured: {missing_s3_configs}"
                    )
                )
            return False
        return True

    def _request(self, *args, **kwargs) -> str:
        """Returns the output of OpenSearchDistribution.request() or throws an error.

        Request method can return one of many: Union[Dict[str, any], List[any], int]
        and raise multiple types of errors.

        If int is returned, then throws an exception informing the HTTP request failed.

        Raises:
          - ValueError
          - OpenSearchHttpError
          - requests.HTTPError
        """
        if "retries" not in kwargs.keys():
            kwargs["retries"] = 6
        if "timeout" not in kwargs.keys():
            kwargs["timeout"] = 10
        result = self.charm.opensearch.request(*args, **kwargs)

        # If the return is an int type, then there was a request error:
        if isinstance(result, int):
            raise OpenSearchHttpError(f"Request failed with code {result}")
        return result

    def get_service_status(self, response: Dict[str, Any]) -> BackupServiceState:  # noqa: C901
        """Returns the response status in a Enum.

        Based on:
        https://github.com/opensearch-project/OpenSearch/blob/
            ba78d93acf1da6dae16952d8978de87cb4df2c61/
            server/src/main/java/org/opensearch/OpenSearchServerException.java#L837
        https://github.com/opensearch-project/OpenSearch/blob/
            ba78d93acf1da6dae16952d8978de87cb4df2c61/
            plugins/repository-s3/src/yamlRestTest/resources/rest-api-spec/test/repository_s3/40_repository_ec2_credentials.yml
        """
        try:
            if "error" not in response:
                return BackupServiceState.SUCCESS
            type = response["error"]["root_cause"][0]["type"]
            reason = response["error"]["root_cause"][0]["reason"]
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
        if (
            "bucket" in self.s3_client.get_s3_connection_info()
            and S3_REPOSITORY in response
            and "settings" in response[S3_REPOSITORY]
            and self.s3_client.get_s3_connection_info()["bucket"]
            == response[S3_REPOSITORY]["settings"]["bucket"]
        ):
            return BackupServiceState.REPO_NOT_CREATED_ALREADY_EXISTS
        # Ensure this is not containing any information about snapshots, return SUCCESS
        return self.get_snapshot_status(response)

    def get_snapshot_status(self, response: Dict[str, Any]) -> BackupServiceState:
        """Returns the snapshot status."""
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
