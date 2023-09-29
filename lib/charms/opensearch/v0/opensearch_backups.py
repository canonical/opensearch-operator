# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manages the backup events within the charm.

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


        def _restart_opensearch(self, event: EventBase) -> None:
            ...
            # After a restart has been successfully executed,
            if not self.peers_data.get(Scope.UNIT, "starting", False):
                try:
                    self._stop_opensearch()
                except OpenSearchStopError as e:
                    logger.error(e)
                    event.defer()
                    self.unit.status = WaitingStatus(ServiceIsStopping)
                    return

            self._start_opensearch(event)

            # call the backup method to check if there are any remaining methods:
            self.backup.apply_post_restart_if_needed()            

"""

import logging
import requests
from typing import Any, Dict, List

from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchError,
    OpenSearchHttpError
)

from charms.opensearch.v0.opensearch_plugins import OpenSearchPlugin, OpenSearchPluginConfig


from ops.framework import Object
from ops.model import ActiveStatus, WaitingStatus, ErrorStatus, BlockedStatus, MaintenanceStatus, StatusBase


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
OPENSEARCH_REPOSITORY_NAME = "charmed-s3-repository"


S3_OPENSEARCH_EXTRA_VALUES = {
    "s3.client.default.max_retries": 3,
    "s3.client.default.path_style_access": False,
    "s3.client.default.protocol": "https",
    "s3.client.default.read_timeout": "50s",
    "s3.client.default.use_throttle_retries": True,
}
S3_REPO_BASE_PATH = "/"


REPO_NOT_CREATED_ERR = "repository type [s3] does not exist"
REPO_NOT_ACCESS_ERR = (
    f"[{OPENSEARCH_REPOSITORY_NAME}] path " + f"[{S3_REPO_BASE_PATH}]"
    if S3_REPO_BASE_PATH
    else "" + " is not accessible"
)


class OpenSearchBackupError(OpenSearchError):
    """Exception thrown when an opensearch backup-related action fails."""


class OpenSearchBackupNeworkError(OpenSearchBackupError):
    """Exception thrown when opensearch API call fails."""


class BackupServiceState(BaseStrEnum):
    """Enum for the states possible once plugin is enabled."""

    SUCCESS = "success"
    RESPONSE_FAILED_NETWORK = "response failed: network error"
    REPO_NOT_CREATED = "repository not created"
    REPO_NOT_CREATED_ALREADY_EXISTS = "repo not created as it already exists"
    REPO_MISSING = "repository is missing from request"
    REPO_S3_UNREACHABLE = "repository s3 is unreachable"
    ILLEGAL_ARGUMENT = "request contained wrong argument"
    SNAPSHOT_MISSING = "snapshot not found"
    SNAPSHOT_RESTORE_ERROR = "restore of snapshot failed"
    SNAPSHOT_IN_PROGRESS = "snapshot in progress"
    SNAPSHOT_PARTIALLY_TAKEN = "snapshot partial: at least one shard missing"
    SNAPSHOT_INCOMPATIBILITY = "snapshot failed: incompatibility issues"
    SNAPSHOT_FAILED_UNKNOWN = "snapshot failed for unknown reason"


class OpenSearchBackupPlugin(OpenSearchPlugin):
    """Manage backup configurations.

    This class must load the opensearch plugin: repository-s3 and configure it.
    """

    def name(self) -> str:
        """Returns the name of the plugin."""
        return "repository-s3"

    def config(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin addition.

        Format:
        OpenSearchPluginConfig(
            config_entries_to_add = {...},
            config_entries_to_del = [...],
            secret_entries_to_add = {...},
            secret_entries_to_del = [...],
        )
        """
        return OpenSearchPluginConfig(
            config_entries_to_add = {
                **S3_OPENSEARCH_EXTRA_VALUES,
                "s3.client.default.region": self._extra_config["region"],
                "s3.client.default.endpoint": self._extra_config["endpoint"],
            },
            secret_entries_to_add = {
                "s3.client.default.access_key": self._extra_config["access-key"],
                "s3.client.default.secret_key": self._extra_config["secret-key"],
            },
        )

    def disable(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin removal.

        Format:
        OpenSearchPluginConfig(
            config_entries_to_add = {...},
            config_entries_to_del = [...],
            secret_entries_to_add = {...},
            secret_entries_to_del = [...],
        )
        """
        return OpenSearchPluginConfig(
            config_entries_to_del = [
                *(S3_OPENSEARCH_EXTRA_VALUES.keys()),
                "s3.client.default.region",
                "s3.client.default.endpoint",
            ],
            secret_entries_to_del = [
                "s3.client.default.access_key",
                "s3.client.default.secret_key",
            ],
        )


class OpenSearchBackup(Object):
    """Implements backup relation and API management."""

    def __init__(self, charm: Object):
        """Manager of OpenSearch client relations."""
        super().__init__(charm)
        self.charm = charm
        # s3 relation handles the config options for s3 backups
        self.s3_client = S3Requirer(self.charm, S3_RELATION)
        self.framework.observe(
            self.charm.on[S3_RELATION].relation_departed, self.on_s3_depart
        )
        self.framework.observe(
            self.s3_client.on.credentials_changed, self.on_s3_change
        )

    @property
    def _plugin(self) -> OpenSearchPlugin:
        return self.charm.plugin_manager.get_plugin(type(self))

    def on_s3_change(self, _) -> None:
        """Calls the plugin manager config handler.

        The S3 change will run over the plugin and verify if the relation is availble if
        the s3 config was completely provided. Otherwise, abandon the event and wait for
        a next relation change.
        """
        if not self._check_missing_s3_config_completeness():
            # Abandon this event, as it is still missing data
            return
        # Let run() happens: it will check if the relation is present, and if yes, return
        # true if the install / configuration / disabling of backup has happened.
        if self.charm.plugin_manager.run():
            self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
                callback_override="_restart_opensearch"
            )

    def apply_post_restart_if_needed(self) -> None:
        """Runs the post restart routine and API calls needed to setup/disable backup.

        This method should be called by the charm in its restart callback resolution.
        """
        if not self.charm.is_leader():
            return

        if not self._check_missing_s3_config_completeness():
            # Always check if a relation actually exists and if options are available
            # in this case, seems one of the conditions above is not yet present
            # abandon this restart event, as it will be called later once s3 configuration
            # is correctly set
            return

        if self.charm.plugin_manager.status(self._plugin) not in [PluginState.ENABLED, PluginState.WAITING_FOR_UPGRADE]:
            # Configuration is available, but this restart was not done to implement the
            # new backup configs. Abandon the event.
            return

        if self._service_already_registered():
            # Finally, check if all the options above are true AND the configuration has
            # already been applied. If that is the case, then also leave the event.
            return

        # Backup relation has been recently made available with all the parameters needed.
        # Steps: 
        #     (1) set up as maintenance;
        self.charm.unit.status = MaintenanceStatus("Configuring backup service...")
        #     (2) run the request; and
        state = self.get_service_status(self._register_snapshot_repo())
        #     (3) based on the response, set the message status
        if state == BackupServiceState.SUCCESS:
            self.charm.unit.status = ActiveStatus("Backup is active")
        else:
            self.charm.unit.status = BlockedStatus(f"Backup setup failed with {state}")

    def on_s3_depart(self, event: EventBase) -> None:
        """Processes the departure of s3. It runs the reverse process of on_s3_change:

        1) Check if the cluster is currently taking a snapshot, if yes, set status as blocked
           and defer this event.
        2) If leader, run API calls to signal disable is needed
        3) Update opensearch.yml and keystore
        4) Emit a restart event
        """
        self.charm.unit.status = MaintenanceStatus("Disabling backup service...")
        snap_status = self._check_snapshot_status()
        if snap_status in [
            BackupServiceState.SNAPSHOT_IN_PROGRESS,
            BackupServiceState.SNAPSHOT_PARTIALLY_TAKEN
        ]:
            # 1) snapshot is either in progress or partially taken: block and defer this event
            self.charm.unit.status = BlockedStatus(f"Disabling backup not possible: {snap_status}")
            event.defer()

        if self.charm.is_leader():
            # 2) Run the API calls
            self._execute_s3_depart_calls()

        # 3) and 4) Remove configuration and issue restart request
        if self.charm.plugin_manager.run():
            self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
                callback_override="_restart_opensearch"
            )
        self.charm.unit.status = MaintenanceStatus("Disabling backup service: restarting service")

    def _execute_s3_depart_calls(self):
        """Executes the s3 departure API calls."""
        return  # do not execute anything as we intend to keep the backups untouched

    def _check_repo_status(self) -> BackupServiceState:
        try:
            return self.get_snapshot_status(self._request("GET", f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}"))
        except OpenSearchBackupNeworkError:
            return BackupServiceState.RESPONSE_FAILED_NETWORK

    def _check_snapshot_status(self) -> BackupServiceState:
        try:
            return self.get_snapshot_status(self._request("GET", "/_snapshot/_status"))
        except OpenSearchBackupNeworkError:
            return BackupServiceState.RESPONSE_FAILED_NETWORK

    def _service_already_registered(self, bucket_name: str = "") -> bool:
        """Returns True if the snapshot repo has already been created.

        If bucket_name is set, then compare it in the response as well.
        """
        state = self._check_repo_status()
        if state == BackupServiceState.SUCCESS:
            # Repo already present
            return True
        return False

    def _register_snapshot_repo(self) -> BackupServiceState:
        """Registers the snapshot repo in the cluster."""
        info = self.s3_client.get_s3_connection_info()
        bucket_name = info["bucket"]
        return self.get_service_status(
                self._request(
                "PUT",
                f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}",
                payload={
                    "type": "s3",
                    "settings": {
                        "bucket": bucket_name,
                        "base_path": S3_REPO_BASE_PATH,
                    },
                },
            )
        )

    def _check_missing_s3_config_completeness(self) -> List[str]:
        """Checks if relation is set and all configs needed are present.

        The get_s3_connection_info() checks if the relation is present, and if yes,
        returns the data in it.

        This method will go over the output and generate a list of missing parameters
        that are manadatory to have be present. An empty list means everything is present.
        """
        return [
            config
            for config in ["region", "bucket", "access-key", "secret-key"]
            if config not in self.s3_client.get_s3_connection_info()
        ]

    def _request(self, *args, **kwargs) -> str:
        """Returns the output of OpenSearchDistribution.request() or throws an error.

        Request method can return one of many: Union[Dict[str, any], List[any], int]
        and raise multiple types of errors.

        If int is returned, then throws an exception informing the HTTP request failed.
        """

        try:
            result = self.charm.opensearch.request(args, kwargs)
        except (
            ValueError, OpenSearchHttpError, requests.HTTPError
        ):
            raise OpenSearchBackupNeworkError()
        
        # The request() method returns some possible exceptions. Let it raise these
        # exceptions in this case. If the return is an int type, then there was a
        # request error:
        if isinstance(result, int):
            raise OpenSearchBackupNeworkError(f"Request failed with code {result}")
        return result

    def get_service_status(self, response: Dict[str, Any]) -> BackupServiceState:
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
            "bucket" in self.s3_client.get_s3_connection_info() and
            OPENSEARCH_REPOSITORY_NAME in response and
            "settings" in response[OPENSEARCH_REPOSITORY_NAME] and
            self.s3_client.get_s3_connection_info()["bucket"] == \
                response[OPENSEARCH_REPOSITORY_NAME]["settings"]["bucket"]
        ):
            return BackupServiceState.REPO_NOT_CREATED_ALREADY_EXISTS
        return BackupServiceState.SUCCESS

    def get_snapshot_status(self, response: Dict[str, Any]) -> BackupServiceState:
        """Returns the snapshot status."""
        # Now, check snapshot status:
        r_str = str(response)
        if "SUCCESS" in r_str:
            return BackupServiceState.SUCCESS
        if "IN_PROGRESS" in r_str:
            return BackupServiceState.SNAPSHOT_IN_PROGRESS
        if "PARTIAL" in r_str:
            return BackupServiceState.SNAPSHOT_PARTIALLY_TAKEN
        if "INCOMPATIBLE" in r_str:
            return BackupServiceState.SNAPSHOT_INCOMPATIBILITY
        if "FAILED" in r_str:
            return BackupServiceState.SNAPSHOT_FAILED_UNKNOWN
        return BackupServiceState.SUCCESS