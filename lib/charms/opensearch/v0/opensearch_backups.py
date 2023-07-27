# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class, we manage backup configurations and actions.

This class must load the opensearch plugin: s3-repository; and configure it.
"""

import json
import logging

from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.opensearch.v0.constants_charm import OPENSEARCH_REPOSITORY_NAME, S3_RELATION
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchBackupBusyError,
    OpenSearchHttpError,
    OpenSearchPluginError,
    OpenSearchKeystoreError,
    OpenSearchUnknownBackupRestoreError,
)
from ops.framework import Object
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, StatusBase

# The unique Charmhub library identifier, never change it
LIBID = "d704d9bd5688480a9cf408d62cff3bcb"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OpenSearchBackup(Object):
    """In this class, we manage OpenSearch backups."""

    def __init__(self, charm):
        """Manager of OpenSearch client relations."""
        super().__init__(charm, S3_RELATION)
        self.charm = charm
        self.distro = self.charm.opensearch

        # s3 relation handles the config options for s3 backups
        self.s3_client = S3Requirer(self.charm, S3_RELATION)
        # Used to ensure s3-repository plugin is loaded
        self.framework.observe(
            self.charm.on[S3_RELATION].relation_joined, self._on_s3_credential_joined
        )
        self.framework.observe(
            self.charm.on[S3_RELATION].relation_departed, self._on_s3_credential_departed
        )

        self.framework.observe(
            self.s3_client.on.credentials_changed, self._on_s3_credential_changed
        )
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_action)
        self.framework.observe(self.charm.on.restore_action, self._on_get_backup_status_action)

    def _on_s3_credential_joined(self, event):
        """Loads the s3 plugin."""
        try:
            self.distro.add_plugin_without_restart("repository-s3", batch=True)
        except OpenSearchPluginError:
            logger.info("Plugin error registered, expected if plugin already installed")
            event.defer()
            return

    def _on_s3_credential_departed(self, _):
        """Unloads the s3 plugin."""
        self.distro.remove_plugin_without_restart("repository-s3")
        self.charm.opensearch_config.del_s3_parameters()
        self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
            callback_override="self.charm._restart_opensearch"
        )

    def _on_s3_credential_changed(self, event) -> None:
        """Sets credentials, resyncs if necessary and reports config errors."""
        try:
            self.charm.opensearch_config.set_s3_parameters(self.s3_client.get_s3_connection_info())
        except OpenSearchKeystoreError:
            logger.warn("Keystore error: missing credential, defer event...")
            event.defer()
            return
        self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
            callback_override="self.charm._restart_opensearch"
        )

    def _get_backup_status(self) -> StatusBase:
        """Get the backup status."""
        try:
            response = self.request("GET", "/_snapshot/_status").text
        except OpenSearchHttpError as e:
            raise e
        except Exception as e:
            raise OpenSearchUnknownBackupRestoreError(
                f"""Unknown backup failure, response: {response.text}
                    Error: {e.__traceback__}"""
            )

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
            return BlockedStatus("backup failed: unknown")
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
            response = self.request(
                "GET",
                f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}/_all",
            )
            if isinstance(response.text, str):
                r = json.dumps(response.text)
            else:
                r = response.text
            # 0, as the very first backup will be 1
            res = 0
            for b in r["snapshots"]:
                if res < b:
                    res = b
            return res

        except (OpenSearchHttpError, OpenSearchBackupBusyError) as e:
            raise e
        except Exception as e:
            raise OpenSearchUnknownBackupRestoreError(
                f"""Unknown backup failure, response: {response.text}
                    Error: {e.__traceback__}"""
            )

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
            event.fail(f"Failed with error:\n{e.__traceback__}")
        event.set_results(status)

    def _on_create_backup_action(self, event: StatusBase) -> None:
        """Answers the backup action from the operator."""
        try:
            if not self._on_action_run_prechecks(event):
                # The prechecks already set the event fail condition, just return
                return

            code = self._get_latest_backup_code()
            code += 1

            response = self.request(
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
            raise OpenSearchUnknownBackupRestoreError(
                f"""Unknown backup failure, response: {response.text}
                    Error: {e.__traceback__}"""
            )

    def _on_list_backups_action(self, event: StatusBase) -> None:
        try:
            response = self.request(
                "GET",
                f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}/_alls",
            )
        except (OpenSearchHttpError, OpenSearchBackupBusyError) as e:
            raise e
        except Exception as e:
            raise OpenSearchUnknownBackupRestoreError(
                f"""Unknown backup failure, response: {response}
                    Error: {e.__traceback__}"""
            )
        event.set_result(f"{response.text}")

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

            response = self.request(
                "PUT",
                f"_snapshot/{OPENSEARCH_REPOSITORY_NAME}/{backup_id}/_restore",
                payload=payload,
            )
        except (OpenSearchHttpError, OpenSearchBackupBusyError) as e:
            raise e
        except Exception as e:
            raise OpenSearchUnknownBackupRestoreError(
                f"""Unknown backup failure, response: {response.text}
                    Error: {e.__traceback__}"""
            )
