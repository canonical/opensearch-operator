# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Backup.

This file holds the implementation of the OpenSearchBackup, OpenSearchBackupPlugin classes
as well as the configuration and state enum.

The OpenSearchBackup class listens to both relation changes from S3_RELATION and API calls
and responses. The OpenSearchBackupPlugin holds the configuration info. The classes together
manages the events related to backup/restore cycles.

The setup of s3-repository happens in two phases: (1) at credentials-changed event, where
the backup configuration is made in opensearch.yml and the opensearch-keystore; (2) when
the first action is requested and the actual registration of the repo takes place.

That needs to be separated in two phases as the configuration itself will demand a restart,
before configuring the actual snapshot repo is possible in OpenSearch.

The removal of backup only reverses step (1), to avoid accidentally deleting the existing
snapshots in the S3 repo.


The main class to interact with is the OpenSearchBackup. This class will observe the s3
relation and backup-related actions.

OpenSearchBackup finishes the config of the backup service once opensearch.yml has bee
set/unset and a restart has been applied. That means, in the case s3 has been related,
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
from typing import Any, Dict

import requests
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchBackupPlugin,
    OpenSearchPluginRelationClusterNotReadyError,
    PluginState,
)
from ops.charm import ActionEvent
from ops.framework import EventBase, Object
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus
from tenacity import RetryError

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


REPO_NOT_CREATED_ERR = "repository type [s3] does not exist"
REPO_NOT_ACCESS_ERR = f"[{S3_REPOSITORY}] path [{S3_REPO_BASE_PATH}] is not accessible"
REPO_CREATING_ERR = "Could not determine repository generation from root blobs"


class OpenSearchBackupError(OpenSearchError):
    """Exception thrown when an opensearch backup-related action fails."""


class OpenSearchListBackupError(OpenSearchBackupError):
    """Exception thrown when internal list backups call fails."""


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
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)

    @property
    def _plugin_status(self):
        return self.charm.plugin_manager.get_plugin_status(OpenSearchBackupPlugin)

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Returns the list of available backups to the user."""
        if not self._check_action_can_run(event):
            event.fail("Failed: backup service is not configured yet")
            return
        backups = {}
        try:
            backups = self._fetch_snapshots()
            event.set_results({"snapshots": (json.dumps(backups)).replace("_", "-")})
        except OpenSearchError as e:
            event.fail(
                f"List backups action failed - {str(e)} - check the application logs for the full stack trace."
            )

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Creates a backup from the current cluster."""
        if not self.charm.unit.is_leader():
            event.fail("Failed: the action can be run only on leader unit")
            return

        if not self._check_action_can_run(event):
            event.fail("Failed: backup service is not configured yet")
            return

        new_backup_id = None
        try:
            # Check if any backup is not running already, or RetryError happens
            if self.is_backup_in_progress():
                event.fail("Backup still in progress: aborting this request...")
                return
            # Increment by 1 the latest snapshot_id (set to 0 if no snapshot was previously made)
            new_backup_id = int(max(self._fetch_snapshots().keys() or [0])) + 1
            logger.debug(
                f"Create backup action request id {new_backup_id} response is:"
                + self.get_service_status(
                    self._request(
                        "PUT",
                        f"_snapshot/{S3_REPOSITORY}/{new_backup_id}?wait_for_completion=false",
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
        except (
            RetryError,
            ValueError,
            OpenSearchHttpError,
            requests.HTTPError,
            OpenSearchListBackupError,
        ) as e:
            event.fail(f"Failed with exception: {e}")
            return
        event.set_results({"backup-id": new_backup_id, "status": "Backup is running."})

    def _check_action_can_run(self, event: ActionEvent) -> bool:
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

    def _fetch_snapshots(self) -> Dict[int, str]:
        """Returns a mapping of snapshot ids / state."""
        response = self._request("GET", f"_snapshot/{S3_REPOSITORY}/_all")
        return {
            snapshot["snapshot"]: snapshot["state"] for snapshot in response.get("snapshots", [])
        }

    def is_backup_in_progress(self, backup_id=None) -> bool:
        """Returns True if backup is in progress, False otherwise."""
        return self._query_backup_status(backup_id) in [
            BackupServiceState.SNAPSHOT_IN_PROGRESS,
        ]

    def _query_backup_status(self, backup_id=None) -> BackupServiceState:
        target = f"_snapshot/{S3_REPOSITORY}/"
        target += f"{backup_id}" if backup_id else "_all"
        output = self._request("GET", target)
        logger.debug(f"Backup status: {output}")
        return self.get_service_status(output)

    def _on_s3_credentials_changed(self, event: EventBase) -> None:
        """Calls the plugin manager config handler.

        The S3 change will run over the plugin and verify if the relation is available if
        the s3 config was completely provided. Otherwise, abandon the event and wait for
        a next relation change.
        """
        if not self._is_s3_fully_configured():
            # Abandon this event, as it is still missing data
            return

        if self.s3_client.get_s3_connection_info().get("tls-ca-chain"):
            raise NotImplementedError

        # Let run() happens: it will check if the relation is present, and if yes, return
        # true if the install / configuration / disabling of backup has happened.
        try:
            if self.charm.plugin_manager.run():
                self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
                    callback_override="_restart_opensearch"
                )
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
        self.charm.status.clear(ActiveStatus())

    def apply_post_restart_if_needed(self) -> None:
        """Runs the post restart routine and API calls needed to setup/disable backup.

        This method should be called by the charm in its restart callback resolution.
        """
        if not self.charm.unit.is_leader():
            return

        if not self._is_s3_fully_configured():
            # Always check if a relation actually exists and if options are available
            # in this case, seems one of the conditions above is not yet present
            # abandon this restart event, as it will be called later once s3 configuration
            # is correctly set
            return

        if self._plugin_status not in [
            PluginState.ENABLED,
            PluginState.WAITING_FOR_UPGRADE,
        ]:
            # Configuration is available, but this restart was not done to implement the
            # new backup configs. Abandon the event.
            return

        if self._check_repo_status() == BackupServiceState.SUCCESS:
            # Finally, check if all the options above are true AND the configuration has
            # already been applied. If that is the case, then also leave the event.
            return

        # Backup relation has been recently made available with all the parameters needed.
        # Steps:
        #     (1) set up as maintenance;
        self.charm.status.set(MaintenanceStatus("Configuring backup service..."))
        #     (2) run the request; and
        state = self._register_snapshot_repo()
        #     (3) based on the response, set the message status
        if state == BackupServiceState.SUCCESS:
            self.charm.status.set(ActiveStatus("Backup service configured"))
        else:
            self.charm.status.set(BlockedStatus(f"Backup setup failed with {state}"))

    def _on_s3_broken(self, event: EventBase) -> None:
        """Processes the broken s3 relation.

        It runs the reverse process of on_s3_change:
        1) Check if the cluster is currently taking a snapshot, if yes, set status as blocked
           and defer this event.
        2) If leader, run API calls to signal disable is needed
        """
        if self.charm.model.get_relation(S3_RELATION).units:
            # There are still members in the relation, defer until it is finished
            event.defer()
            return
        self.charm.status.set(MaintenanceStatus("Disabling backup service..."))
        snapshot_status = self._check_snapshot_status()
        if snapshot_status in [
            BackupServiceState.SNAPSHOT_IN_PROGRESS,
        ]:
            # 1) snapshot is either in progress or partially taken: block and defer this event
            self.charm.status.set(
                BlockedStatus(f"Disabling backup not possible: {snapshot_status}")
            )
            event.defer()
            return
        if snapshot_status in [
            BackupServiceState.SNAPSHOT_PARTIALLY_TAKEN,
        ]:
            logger.warning(
                "Snapshot has been partially taken, but not completed. Continuing with relation removal..."
            )

        # Run the check here, as we want all the units to keep deferring the event if needed.
        # That avoids a condition where we have:
        # 1) A long snapshot is taking place
        # 2) Relation is removed
        # 3) Only leader is checking for that and deferring the event
        # 4) The leader is lost or removed
        # 5) The snapshot is removed: self._execute_s3_broken_calls() never happens
        if self.charm.unit.is_leader():
            # 2) Run the API calls
            self._execute_s3_broken_calls()

        try:
            if self.charm.plugin_manager.run():
                self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
                    callback_override="_restart_opensearch"
                )
        except OpenSearchError as e:
            if isinstance(e, OpenSearchPluginRelationClusterNotReadyError):
                self.charm.status.set(WaitingStatus("s3-broken event: cluster not ready yet"))
            else:
                self.charm.status.set(
                    BlockedStatus("Unexpected error during plugin configuration, check the logs")
                )
                # There was an unexpected error, log it and block the unit
                logger.error(e)
            event.defer()
            return
        self.charm.status.clear(ActiveStatus())

    def _execute_s3_broken_calls(self):
        """Executes the s3 broken API calls."""
        return  # do not execute anything as we intend to keep the backups untouched

    def _check_repo_status(self) -> BackupServiceState:
        try:
            return self.get_service_status(self._request("GET", f"_snapshot/{S3_REPOSITORY}"))
        except (ValueError, OpenSearchHttpError, requests.HTTPError):
            return BackupServiceState.RESPONSE_FAILED_NETWORK

    def _check_snapshot_status(self) -> BackupServiceState:
        try:
            return self.get_snapshot_status(self._request("GET", "/_snapshot/_status"))
        except (ValueError, OpenSearchHttpError, requests.HTTPError):
            return BackupServiceState.RESPONSE_FAILED_NETWORK

    def _register_snapshot_repo(self) -> BackupServiceState:
        """Registers the snapshot repo in the cluster."""
        info = self.s3_client.get_s3_connection_info()
        bucket_name = info["bucket"]
        return self.get_service_status(
            self._request(
                "PUT",
                f"_snapshot/{S3_REPOSITORY}",
                payload={
                    "type": "s3",
                    "settings": {
                        "bucket": bucket_name,
                        "base_path": info.get("path", S3_REPO_BASE_PATH),
                    },
                },
            )
        )

    def _is_s3_fully_configured(self) -> bool:
        """Checks if relation is set and all configs needed are present.

        The get_s3_connection_info() checks if the relation is present, and if yes,
        returns the data in it.

        This method will go over the output and generate a list of missing parameters
        that are manadatory to have be present. An empty list means everything is present.
        """
        missing_s3_configs = [
            config
            for config in ["region", "bucket", "access-key", "secret-key"]
            if config not in self.s3_client.get_s3_connection_info()
        ]
        if missing_s3_configs:
            logger.warn(f"Missing following configs {missing_s3_configs} in s3 relation")
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
