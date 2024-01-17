# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
import logging
import unittest
from unittest.mock import MagicMock, PropertyMock, patch

import charms
import tenacity
from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.opensearch_backups import (
    S3_RELATION,
    S3_REPOSITORY,
    BackupServiceState,
    OpenSearchBackupPlugin,
    OpenSearchListBackupError,
    OpenSearchRestoreFailedClosingIdxError,
    OpenSearchRestoreMismatchBetweenIdxAndSnapshotError,
)
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_plugins import OpenSearchPluginConfig, PluginState
from ops.testing import Harness

from charm import OpenSearchOperatorCharm

TEST_BUCKET_NAME = "s3://bucket-test"
TEST_BASE_PATH = "/test"


LIST_BACKUPS_TRIAL = """ backup-id  | backup-status
---------------------------
 backup1   | finished
 backup2   | snapshot failed for unknown reason
 backup3   | snapshot in progress"""


class TestBackups(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm
        # Override the config to simulate the TestPlugin
        # As config.yaml does not exist, the setup below simulates it
        self.charm.plugin_manager._charm_config = self.harness.model._config
        self.plugin_manager = self.charm.plugin_manager
        # Override the ConfigExposedPlugins
        charms.opensearch.v0.opensearch_plugin_manager.ConfigExposedPlugins = {
            "repository-s3": {
                "class": OpenSearchBackupPlugin,
                "config": None,
                "relation": "s3-credentials",
            },
        }
        self.charm.opensearch.is_started = MagicMock(return_value=True)
        self.charm.health.apply = MagicMock(return_value=HealthColors.GREEN)
        # Mock retrials to speed up tests
        charms.opensearch.v0.opensearch_backups.wait_fixed = MagicMock(
            return_value=tenacity.wait.wait_fixed(0.1)
        )

        # Replace some unused methods that will be called as part of set_leader with mock
        self.charm._put_admin_user = MagicMock()
        self.peer_id = self.harness.add_relation(PeerRelationName, "opensearch")
        self.harness.set_leader(is_leader=True)

        # Relate and run first check
        with patch(
            "charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager.run"
        ) as mock_pm_run:
            self.s3_rel_id = self.harness.add_relation(S3_RELATION, "s3-integrator")
            self.harness.add_relation_unit(self.s3_rel_id, "s3-integrator/0")
            mock_pm_run.assert_not_called()

    def test_get_endpoint_protocol(self) -> None:
        """Tests the get_endpoint_protocol method."""
        assert self.charm.backup._get_endpoint_protocol("http://10.0.0.1:8000") == "http"
        assert self.charm.backup._get_endpoint_protocol("https://10.0.0.2:8000") == "https"
        assert self.charm.backup._get_endpoint_protocol("test.not-valid-url") == "https"

    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager.status")
    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup.apply_api_config_if_needed")
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._apply_config")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version")
    def test_00_update_relation_data(self, __, mock_apply_config, _, mock_status) -> None:
        """Tests if new relation without data returns."""
        mock_status.return_value = PluginState.INSTALLED
        self.harness.update_relation_data(
            self.s3_rel_id,
            "s3-integrator",
            {
                "bucket": TEST_BUCKET_NAME,
                "access-key": "aaaa",
                "secret-key": "bbbb",
                "path": TEST_BASE_PATH,
                "endpoint": "localhost",
                "region": "testing-region",
                "storage-class": "storageclass",
            },
        )
        assert (
            mock_apply_config.call_args[0][0].__dict__
            == OpenSearchPluginConfig(
                secret_entries_to_del=[
                    "s3.client.default.access_key",
                    "s3.client.default.secret_key",
                ],
                secret_entries_to_add={
                    "s3.client.default.access_key": "aaaa",
                    "s3.client.default.secret_key": "bbbb",
                },
            ).__dict__
        )

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager.status")
    def test_01_apply_api_config_if_needed(self, mock_status, _, mock_request) -> None:
        """Tests the application of post-restart steps."""
        self.harness.update_relation_data(
            self.s3_rel_id,
            "s3-integrator",
            {
                "bucket": TEST_BUCKET_NAME,
                "access-key": "aaaa",
                "secret-key": "bbbb",
                "path": TEST_BASE_PATH,
                "endpoint": "localhost",
                "region": "testing-region",
                "storage-class": "storageclass",
            },
        )
        mock_status.return_value = PluginState.ENABLED
        self.charm.backup.apply_api_config_if_needed()
        mock_request.assert_called_with(
            "PUT",
            f"_snapshot/{S3_REPOSITORY}",
            payload={
                "type": "s3",
                "settings": {
                    "endpoint": "localhost",
                    "protocol": "https",
                    "bucket": TEST_BUCKET_NAME,
                    "base_path": TEST_BASE_PATH,
                    "region": "testing-region",
                    "storage_class": "storageclass",
                },
            },
        )

    def test_02_on_list_backups_action(self):
        event = MagicMock()
        event.params = {"output": "table"}
        self.charm.backup._list_backups = MagicMock(return_value={"backup1": {"state": "SUCCESS"}})
        self.charm.backup._generate_backup_list_output = MagicMock(
            return_value="backup1 | finished"
        )
        self.charm.backup._on_list_backups_action(event)
        event.set_results.assert_called_with({"backups": "backup1 | finished"})

    def test_03_on_list_backups_action_in_json_format(self):
        event = MagicMock()
        event.params = {"output": "json"}
        self.charm.backup._list_backups = MagicMock(return_value={"backup1": {"state": "SUCCESS"}})
        self.charm.backup._generate_backup_list_output = MagicMock(
            return_value="backup1 | finished"
        )
        self.charm.backup._on_list_backups_action(event)
        event.set_results.assert_called_with({"backups": '{"backup1": {"state": "SUCCESS"}}'})

    def test_04_check_if_restore_finished(self):
        rel = MagicMock()
        rel.data = {self.charm.app: {"restore_in_progress": "index1,index2"}}
        self.charm.model.get_relation = MagicMock(return_value=rel)
        self.charm.backup._request = MagicMock(
            return_value={
                "index1": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
                "index2": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
                "index3": {"shards": [{"type": "PRIMARY", "stage": "DONE"}]},
            }
        )
        result = self.charm.backup._check_if_restore_finished()
        self.assertTrue(result)

    def test_05_on_check_restore_status_action(self):
        event = MagicMock()
        self.charm.backup._check_if_restore_finished = MagicMock(return_value=True)
        self.charm.backup._on_check_restore_status_action(event)
        self.assertTrue(event.set_results.called)

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup.apply_api_config_if_needed")
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._apply_config")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._execute_s3_broken_calls")
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager.status")
    def test_20_relation_broken(
        self,
        mock_status,
        mock_execute_s3_broken_calls,
        mock_request,
        mock_apply_config,
        _,
    ) -> None:
        """Tests broken relation unit."""
        mock_request.side_effects = [
            # list of returns for each call
            # 1st request: _check_snapshot_status
            # Return a response with SUCCESS in:
            {"SUCCESS"},
        ]
        mock_status.return_value = PluginState.ENABLED
        self.harness.remove_relation_unit(self.s3_rel_id, "s3-integrator/0")
        self.harness.remove_relation(self.s3_rel_id)
        mock_request.called_once_with("GET", "/_snapshot/_status")
        mock_execute_s3_broken_calls.assert_called_once()
        assert (
            mock_apply_config.call_args[0][0].__dict__
            == OpenSearchPluginConfig(
                secret_entries_to_del=[
                    "s3.client.default.access_key",
                    "s3.client.default.secret_key",
                ],
            ).__dict__
        )

    @patch("charms.opensearch.v0.opensearch_backups.ClusterState.indices")
    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_close_indices_if_needed(self, mock_request, mock_indices):
        # Mock the ClusterState.indices method to return a sample index state
        mock_indices.return_value = {
            "index1": {"status": "open"},
            "index2": {"status": "close"},
            "index3": {"status": "open"},
        }
        mock_request.side_effect = [
            # Response from GET _snapshot/{S3_REPOSITORY}/_all
            {
                "snapshots": [
                    {
                        "snapshot": "1",
                        "indices": ["index1", "index2", "index3"],
                        "state": "SUCCESS",
                    },
                    {
                        "snapshot": "2",
                        "indices": ["index4"],
                        "state": "SUCCESS",
                    },
                ]
            },
            # Response from POST /_close
            {
                "acknowledged": True,
                "indices": {"index1": {}},
            },
            # Response from POST /_close
            {
                "acknowledged": True,
                "indices": {"index3": {}},
            },
        ]
        # Call the _close_indices_if_needed method
        closed_indices = self.charm.backup._close_indices_if_needed("1")
        mock_request.assert_any_call("POST", "index1/_close")
        mock_request.assert_any_call("POST", "index3/_close")
        self.assertEqual(closed_indices, {"index1", "index3"})

    @patch("charms.opensearch.v0.opensearch_backups.ClusterState.indices")
    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_close_indices_if_needed_retry_error(self, mock_request, mock_indices):
        mock_indices.return_value = {
            "index1": {"status": "open"},
            "index2": {"status": "close"},
            "index3": {"status": "open"},
        }
        mock_request.side_effect = [
            # Response from GET _snapshot/{S3_REPOSITORY}/_all
            {
                "snapshots": [
                    {
                        "snapshot": "1",
                        "indices": ["index1", "index2", "index3"],
                        "state": "SUCCESS",
                    },
                    {
                        "snapshot": "2",
                        "indices": ["index4"],
                        "state": "SUCCESS",
                    },
                ]
            },
            OpenSearchHttpError,
        ]
        # Call the _close_indices_if_needed method and assert that it raises an exception
        with self.assertRaises(OpenSearchRestoreFailedClosingIdxError):
            self.charm.backup._close_indices_if_needed("1")

    def test_restore_finished_single_unit(self):
        self.charm.backup.model.get_relation = MagicMock(return_value=None)
        result = self.charm.backup._check_if_restore_finished()
        self.assertTrue(result)

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_restore_finished_empty_restore_in_progress(self, mock_request):
        class RelationData:
            def __init__(self, app):
                self.data = {app: {}}

        mock_request.return_value = {
            "index1": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
            "index2": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
        }
        self.charm.backup.model.get_relation = MagicMock(return_value=RelationData(self.charm.app))
        result = self.charm.backup._check_if_restore_finished()
        self.assertTrue(result)

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_restore_finished_all_indices_open(self, mock_request):
        class RelationData:
            def __init__(self, app):
                self.data = {app: {"restore_in_progress": "index1,index2"}}

        self.charm.backup.model.get_relation = MagicMock(return_value=RelationData(self.charm.app))
        mock_request.return_value = {
            "index1": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
            "index2": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
        }
        result = self.charm.backup._check_if_restore_finished()
        self.assertTrue(result)

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_restore_finished_not_all_indices_open(self, mock_request):
        class RelationData:
            def __init__(self, app):
                self.data = {app: {"restore_in_progress": "index1,index2"}}

        self.charm.backup.model.get_relation = MagicMock(return_value=RelationData(self.charm.app))
        mock_request.return_value = {
            "index1": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
            "index2": {"shards": [{"type": "SNAPSHOT", "stage": "IN_PROGRESS"}]},
        }
        result = self.charm.backup._check_if_restore_finished()
        self.assertFalse(result)

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_restore_finished_indices_not_found(self, mock_request):
        class RelationData:
            def __init__(self, app):
                self.data = {app: {"restore_in_progress": "index1,index2"}}

        self.charm.backup.model.get_relation = MagicMock(return_value=RelationData(self.charm.app))
        mock_request.return_value = {
            "index3": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
            "index4": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
        }
        with self.assertRaises(OpenSearchRestoreMismatchBetweenIdxAndSnapshotError):
            self.charm.backup._check_if_restore_finished()

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_restore_finished_leader(self, mock_request):
        class RelationData:
            def __init__(self, app):
                self.data = {app: {"restore_in_progress": "index1,index2"}}

        self.charm.backup.model.get_relation = MagicMock(return_value=RelationData(self.charm.app))
        mock_request.return_value = {
            "index1": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
            "index2": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
        }
        result = self.charm.backup._check_if_restore_finished()
        self.assertTrue(result)
        assert self.charm.backup.model.get_relation.return_value.data == {self.charm.app: {}}

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_restore_finished_not_leader(self, mock_request):
        self.charm.backup.charm.unit.is_leader = MagicMock(return_value=False)

        class RelationData:
            def __init__(self, app):
                self.data = {app: {"restore_in_progress": "index1,index2"}}

        self.charm.backup.model.get_relation = MagicMock(return_value=RelationData(self.charm.app))
        mock_request.return_value = {
            "index1": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
            "index2": {"shards": [{"type": "SNAPSHOT", "stage": "DONE"}]},
        }
        result = self.charm.backup._check_if_restore_finished()
        self.assertFalse(result)
        assert self.charm.backup.model.get_relation.return_value.data == {
            self.charm.app: {"restore_in_progress": "index1,index2"}
        }

    def test_98_format_backup_list(self):
        """Tests the format of the backup list."""
        backup_list = {
            "backup1": {"state": "SUCCESS"},
            "backup2": {"state": "FAILED"},
            "backup3": {"state": "IN_PROGRESS"},
        }
        self.assertEqual(
            self.charm.backup._generate_backup_list_output(backup_list), LIST_BACKUPS_TRIAL
        )

    def test_99_on_update_status(self):
        """Tests a simple update status call."""
        self.charm.backup._check_repo_status = MagicMock(return_value=BackupServiceState.SUCCESS)
        self.charm.backup.is_backup_in_progress = MagicMock(return_value=False)
        self.charm.backup._check_if_restore_finished = MagicMock(return_value=True)
        logger = logging.getLogger("charms.opensearch.v0.opensearch_backups")
        with patch.object(logger, "info") as logger_info_mock:
            self.charm.backup._on_update_status(None)
            logger_info_mock.assert_any_call("Checking if backup in progress: False")
            logger_info_mock.assert_any_call("Checking if restore in progress: True")
        self.charm.backup._check_repo_status.assert_called_once()
        self.charm.backup.is_backup_in_progress.assert_called_once()
        self.charm.backup._check_if_restore_finished.assert_called_once()

    def test_can_unit_perform_backup_plugin_not_ready(self):
        plugin_method = "charms.opensearch.v0.opensearch_backups.OpenSearchBackup._plugin_status"
        event = MagicMock()
        with patch(plugin_method, new_callable=PropertyMock) as mock_plugin_status:
            mock_plugin_status.return_value = PluginState.DISABLED
            result = self.charm.backup._can_unit_perform_backup(event)
        event.fail.assert_called_with(
            "Failed: plugin is not ready yet, current status is disabled"
        )
        self.assertFalse(result)

    def test_can_unit_perform_backup_repo_status_failed(self):
        plugin_method = "charms.opensearch.v0.opensearch_backups.OpenSearchBackup._plugin_status"
        event = MagicMock()
        with patch(plugin_method, new_callable=PropertyMock) as mock_plugin_status:
            mock_plugin_status.return_value = PluginState.ENABLED
            self.charm.backup._check_repo_status = MagicMock(
                return_value=BackupServiceState.REPO_NOT_CREATED
            )
            result = self.charm.backup._can_unit_perform_backup(event)
        event.fail.assert_called_with("Failed: repo status is repository not created")
        self.assertFalse(result)

    def test_can_unit_perform_backup_backup_in_progress(self):
        plugin_method = "charms.opensearch.v0.opensearch_backups.OpenSearchBackup._plugin_status"
        event = MagicMock()
        with patch(plugin_method, new_callable=PropertyMock) as mock_plugin_status:
            mock_plugin_status.return_value = PluginState.ENABLED
            self.charm.backup._check_repo_status = MagicMock(
                return_value=BackupServiceState.SUCCESS
            )
            self.charm.backup.is_backup_in_progress = MagicMock(return_value=True)
            result = self.charm.backup._can_unit_perform_backup(event)
        self.assertFalse(event.fail.called)
        self.assertFalse(result)

    def test_can_unit_perform_backup_success(self):
        plugin_method = "charms.opensearch.v0.opensearch_backups.OpenSearchBackup._plugin_status"
        event = MagicMock()
        with patch(plugin_method, new_callable=PropertyMock) as mock_plugin_status:
            mock_plugin_status.return_value = PluginState.ENABLED
            self.charm.backup._check_repo_status = MagicMock(
                return_value=BackupServiceState.SUCCESS
            )
            self.charm.backup.is_backup_in_progress = MagicMock(return_value=False)
            result = self.charm.backup._can_unit_perform_backup(event)
        self.assertFalse(event.fail.called)
        self.assertTrue(result)

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_on_create_backup_action_success_async(self, mock_request):
        class RelationData:
            def __init__(self, app):
                self.data = {app: {}}

        self.charm.backup.model.get_relation = MagicMock(return_value=RelationData(self.charm.app))
        event = MagicMock()
        self.charm.backup._can_unit_perform_backup = MagicMock(return_value=True)
        self.charm.backup.is_backup_in_progress = MagicMock(return_value=False)
        self.charm.backup._list_backups = MagicMock(return_value={})
        self.charm.backup.get_service_status = MagicMock(return_value="Backup completed.")
        event.params = {"wait-for-completion": False}
        self.charm.backup._on_create_backup_action(event)
        event.set_results.assert_called_with({"backup-id": 1, "status": "Backup is running."})
        assert self.charm.backup.model.get_relation.return_value.data == {
            self.charm.app: {"backup_in_progress": "1"}
        }
        assert mock_request.call_args[0][0] == "PUT"
        assert (
            mock_request.call_args[0][1]
            == f"_snapshot/{S3_REPOSITORY}/1?wait_for_completion=false"
        )

    def test_on_create_backup_action_failure(self):
        event = MagicMock()
        self.charm.backup._can_unit_perform_backup = MagicMock(return_value=False)
        self.charm.backup._on_create_backup_action(event)
        event.fail.assert_called_with("Failed: backup service is not configured yet")

    def test_on_create_backup_action_backup_in_progress_async(self):
        event = MagicMock()
        self.charm.backup._can_unit_perform_backup = MagicMock(return_value=True)
        self.charm.backup.is_backup_in_progress = MagicMock(return_value=True)
        event.params = {"wait-for-completion": False}
        self.charm.backup._on_create_backup_action(event)
        event.fail.assert_called_with("Backup still in progress: aborting this request...")

    def test_on_create_backup_action_exception(self):
        event = MagicMock()
        self.charm.backup._can_unit_perform_backup = MagicMock(return_value=True)
        self.charm.backup.is_backup_in_progress = MagicMock(return_value=False)
        self.charm.backup._list_backups = MagicMock(
            side_effect=OpenSearchListBackupError("Backup error")
        )
        event.params = {"wait-for-completion": True}
        self.charm.backup._on_create_backup_action(event)
        event.fail.assert_called_with("Failed with exception: Backup error")

    @patch("charms.opensearch.v0.opensearch_backups.OpenSearchBackup._request")
    def test_on_create_backup_action_success(self, mock_request):
        event = MagicMock()
        self.charm.backup._can_unit_perform_backup = MagicMock(return_value=True)
        self.charm.backup.is_backup_in_progress = MagicMock(return_value=False)
        self.charm.backup._list_backups = MagicMock(return_value={})
        self.charm.backup.get_service_status = MagicMock(return_value="Backup completed.")
        event.params = {"wait-for-completion": True}
        self.charm.backup._on_create_backup_action(event)
        event.set_results.assert_called_with({"backup-id": 1, "status": "Backup completed."})
        assert mock_request.call_args[0][0] == "PUT"
        assert (
            mock_request.call_args[0][1] == f"_snapshot/{S3_REPOSITORY}/1?wait_for_completion=true"
        )
