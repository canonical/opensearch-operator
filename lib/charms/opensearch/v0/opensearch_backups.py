# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class, we manage backup configurations and actions.

This class must load the opensearch plugin: s3-repository; and configure it.
"""

import logging
from typing import List, Union

from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.opensearch.v0.constants_charm import OPENSEARCH_REPOSITORY_NAME, S3_RELATION
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchBackupBusyError,
    OpenSearchHttpError,
    OpenSearchKeystoreError,
    OpenSearchPluginError,
    OpenSearchUnknownBackupRestoreError,
)
from ops.framework import Object
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
    StatusBase,
    WaitingStatus,
)

# The unique Charmhub library identifier, never change it
LIBID = "d704d9bd5688480a9cf408d62cff3bcb"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)

REPO_NOT_CREATED_ERR = "repository type [s3] does not exist"
REPO_BASE_PATH = "/"
REPO_NOT_ACCESS_ERR = (
    f"[{OPENSEARCH_REPOSITORY_NAME}] path " + f"[{REPO_BASE_PATH}]"
    if REPO_BASE_PATH
    else "" + " is not accessible"
)


class OpenSearchBackup(Object):
    """In this class, we manage OpenSearch backups."""

    def __init__(self, charm):
        """Manager of OpenSearch client relations."""
        super().__init__(charm, S3_RELATION)
        self.charm = charm
        self.distro = self.charm.opensearch

        # s3 relation handles the config options for s3 backups
        self.s3_client = S3Requirer(self.charm, S3_RELATION)
        self.framework.observe(
            self.charm.on[S3_RELATION].relation_departed, self._on_s3_credential_departed
        )
        self.framework.observe(
            self.s3_client.on.credentials_changed, self._on_s3_credential_changed
        )
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(
            self.charm.on.get_backup_status_action, self._on_get_backup_status_action
        )
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_action)

    def _is_related_to_s3(self) -> bool:
        return len(self.charm.framework.model.relations[S3_RELATION] or {}) > 0

    def _is_started(self) -> bool:
        return self.distro.is_started()

    def _request(self, *args, **kwargs) -> dict:
        return self.distro.request(*args, **kwargs)

    def check_if_snapshot_repo_created(self, bucket_name: str = "") -> bool:
        """Returns True if the snapshot repo has already been created.

        If bucket_name is set, then compare it in the response as well.
        """
        get = self._request("GET", f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}")
        try:
            if "error" in get:
                # Check if we error'ed b/c of missing snapshot repo
                if get["error"]["root_cause"][0]["type"] != "repository_missing_exception":
                    raise OpenSearchUnknownBackupRestoreError("Snapshot repo is wrongly set")
                return False
            if (
                bucket_name
                and bucket_name not in get["charmed-s3-repository"]["settings"]["bucket"]
            ):
                # bucket name changed, recreate the repo
                return False
        except KeyError:
            # One of the error keys are not present, this is a deeper issue
            raise OpenSearchUnknownBackupRestoreError("Snapshot repo is wrongly set")
        return True

    def _check_s3_config_completeness(self) -> List:
        return [
            c
            for c in ["region", "bucket", "access-key", "secret-key"]
            if c not in self.s3_client.get_s3_connection_info()
        ]

    def register_snapshot_repo(self) -> bool:
        """Registers the snapshot repo in the cluster."""
        info = self.s3_client.get_s3_connection_info()
        bucket_name = info["bucket"]
        try:
            if self.check_if_snapshot_repo_created(bucket_name):
                # We've already created the repo, leaving...
                return True
            put = self._request(
                "PUT",
                f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}",
                payload={
                    "type": "s3",
                    "settings": {
                        "bucket": bucket_name,
                        "base_path": REPO_BASE_PATH,
                    },
                },
            )
            if "error" in put:
                try:
                    # Check if we error'ed b/c s3 repo is not configured, hence we are still
                    # waiting for the plugin to be configured
                    if (
                        put["error"]["root_cause"][0]["type"] == "repository_exception"
                        and REPO_NOT_CREATED_ERR in put["error"]["root_cause"][0]["reason"]
                    ):
                        logger.warn("register_snapshot_repo: repo [s3] not found")
                        return False
                    # Now, check if tried to reach the S3 repo and failed
                    if (
                        put["error"]["root_cause"][0]["type"]
                        == "repository_verification_exception"
                        and REPO_NOT_ACCESS_ERR in put["error"]["root_cause"][0]["reason"]
                    ):
                        logger.warn("register_snapshot_repo: error trying to reach to s3")
                        return False
                except KeyError:
                    # Ignore this error and let the Unknown backup be raised
                    # It means we have a more troubling issue in the cluster
                    pass
            return True
        finally:
            # Unknown condition reached
            raise OpenSearchUnknownBackupRestoreError(
                "register_snapshot_repo - cannot contact the cluster"
            )

    def _on_s3_credential_departed(self, event):
        """Unloads the s3 plugin."""
        try:
            if self.fails_preflight_checks():
                event.defer()
                return
            self.distro.remove_plugin_without_restart("repository-s3")
            self.charm.opensearch_config.del_s3_parameters()
        except OpenSearchKeystoreError:
            logger.error("Keystore error: missing credential, defer event...")
            event.defer()
            return
        self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
            callback_override="_restart_opensearch"
        )

    def _on_s3_credential_changed(self, event) -> None:
        """Sets credentials, resyncs if necessary and reports config errors.

        The first pass in this method should return false for the registration, then the
        backup plugin is installed and configured.
        """
        try:
            if self.fails_preflight_checks():
                event.defer()
                return
            info = self.s3_client.get_s3_connection_info()
            if self.register_snapshot_repo():
                # s3 is set and we've set the snapshot repo, nothing to do here
                return
            self.distro.add_plugin_without_restart("repository-s3", batch=True)
            self.charm.opensearch_config.set_s3_parameters(info)
        except (
            OpenSearchKeystoreError,
            OpenSearchPluginError,
            OpenSearchUnknownBackupRestoreError,
        ) as e:
            logger.exception(e)
            logger.error("Error during backup setup")
            event.defer()
            return
        self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
            callback_override="_restart_opensearch"
        )
        # Now, defer event as we're waiting for a restart
        event.defer()

    def fails_preflight_checks(self) -> Union[StatusBase, None]:
        """Executes common list of preflights before main changes."""
        if not self._is_started():
            return WaitingStatus("Waiting service to come up")
        if self._check_s3_config_completeness():
            return BlockedStatus(f"Missing s3 info: {self._check_s3_config_completeness()}")
        return None

    def _get_backup_status(self) -> StatusBase:  # noqa: C901
        """Get the backup status.

        The possible status are:
        1) No relation available, return active
        2) Backup configuration not finished yet, return MaintenanceStatus
        3) An error occurred during configuration or a backup procedure: return it
        4) Return active
        """
        if not self._is_related_to_s3():
            # It means there is nothing to do in the backup
            return ActiveStatus("")
        if self.fails_preflight_checks():
            return self.preflight_checks()
        try:
            if self.check_if_snapshot_repo_created():
                return ActiveStatus("")
            response = self._request("GET", "/_snapshot/_status")
        except Exception as e:
            logger.exception(e)
            logger.error("Unknown backup failure")
            return BlockedStatus("backup service failed: unknown")

        logger.debug(f"_get_backup_status response: {response}")

        # Check state:
        if "SUCCESS" in response:
            return ActiveStatus("")
        if "IN_PROGRESS" in response:
            return MaintenanceStatus("backup in progress")
        if "PARTIAL" in response:
            return BlockedStatus("partial backup: at least one shard failed to backup")
        if "INCOMPATIBLE" in response:
            return BlockedStatus("backup failed: compatibility problems")
        if "FAILED" in response:
            return BlockedStatus("backup service failed: unknown")
        return ActiveStatus("")

    def _on_action_run_prechecks(self, event: StatusBase) -> bool:
        """Runs the standard checks for backups: is it leader and backup status."""
        if self.model.get_relation(S3_RELATION) is None:
            event.fail("Relation with s3-integrator charm missing, cannot create backup.")
            return False

        # only leader can create backups. This prevents multiple backups from being attempted at
        # once.
        if not self.charm.unit.is_leader():
            event.fail("The action can be run only on leader unit.")
            return False
        if not self._is_related_to_s3():
            event.fail("Missing s3 relation.")
            return False
        # cannot create backup if pbm is not ready. This could be due to: resyncing, incompatible,
        # options, incorrect credentials, or already creating a backup
        status = self._get_backup_status()
        self.charm.unit.status = status
        if isinstance(status, MaintenanceStatus):
            event.fail(
                "Can only create one backup at a time, please wait for current backup to finish."
            )
            return False
        if isinstance(status, BlockedStatus):
            event.fail(f"Cannot create backup {status.message}.")
            return False
        return True

    def _get_latest_backup_code(self) -> int:
        """Returns the latest backup code performed."""
        try:
            response = self._request(
                "GET",
                f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}/_all",
            )
            r = response
            # 0, as the very first backup will be 1
            res = 0
            for b in r.get("snapshots", []):
                if res < b:
                    res = b
            return res if res > 0 else 1

        except (OpenSearchHttpError, OpenSearchBackupBusyError) as e:
            raise e
        except Exception as e:
            logger.exception(e)
            raise OpenSearchUnknownBackupRestoreError("Unknown backup failure")

    def _on_get_backup_status_action(self, event: StatusBase) -> None:
        """Returns the status of the backup plugin."""
        try:
            s = self._get_backup_status()
            if isinstance(s, ActiveStatus):
                status = "backup plugin is idle"
            elif isinstance(s, MaintenanceStatus):
                status = "backup in progress"
            elif isinstance(s, BlockedStatus):
                status = f"ERROR: {s.message}"
        except Exception as e:
            logger.exception(e)
            event.fail("Failed with error, check juju logs")
        event.set_results(status)

    def _on_create_backup_action(self, event: StatusBase) -> None:
        """Answers the backup action from the operator."""
        try:
            if not self._on_action_run_prechecks(event):
                # The prechecks already set the event fail condition, just return
                return

            code = self._get_latest_backup_code()
            code += 1

            self._request(
                "PUT",
                f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}/{code}",
                payload={
                    "indices": event.params.get("indices"),
                    "ignore_unavailable": "false",
                    "include_global_state": "true",
                    "partial": "false",
                },
            )
            event.set_results({"backup-status": "backup started"})
            self.charm.unit.status = MaintenanceStatus("backup started")
        except (OpenSearchHttpError, OpenSearchBackupBusyError) as e:
            raise e
        except Exception as e:
            logger.exception(e)
            raise OpenSearchUnknownBackupRestoreError("Unknown backup failure")

    def _on_list_backups_action(self, event: StatusBase) -> None:
        try:
            response = self._request(
                "GET",
                f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}/_all",
            )
        except OpenSearchBackupBusyError:
            event.fail("Backup is busy")
        except Exception as e:
            logger.exception(e)
            raise OpenSearchUnknownBackupRestoreError("Unknown backup failure")
        event.set_result(f"{response}")

    def _on_restore_action(self, event: StatusBase) -> None:
        try:
            if not self._on_action_run_prechecks(event):
                # The prechecks already set the event fail condition, just return
                return
            backup_id = event.params.get("backup-id")
            payload = {
                "indices": event.params.get("indices"),
                "ignore_unavailable": "false",
                "include_global_state": "true",
                "include_aliases": "true",
                "partial": "false",
                "storage_type": "local",
            }
            # Add optional payloads
            for p in [
                "rename-pattern",
                "rename-replacement",
                "index-settings",
                "ignore-index-settings",
            ]:
                if event.params.get(p):
                    payload[p.replace("-", "_")] = event.params.get(p)

            self._request(
                "PUT",
                f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}/{backup_id}/_restore",
                payload=payload,
            )
        except (OpenSearchHttpError, OpenSearchBackupBusyError) as e:
            raise e
        except Exception as e:
            logger.exception(e)
            raise OpenSearchUnknownBackupRestoreError("Unknown backup failure")
