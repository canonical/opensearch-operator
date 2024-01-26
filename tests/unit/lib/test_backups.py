# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
import unittest
from unittest.mock import MagicMock, patch

import charms
from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.opensearch_backups import (
    S3_RELATION,
    S3_REPOSITORY,
    OpenSearchBackupPlugin,
)
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_plugins import OpenSearchPluginConfig, PluginState
from ops.testing import Harness

from charm import OpenSearchOperatorCharm

TEST_BUCKET_NAME = "s3://bucket-test"
TEST_BASE_PATH = "/test"


class TestBackups(unittest.TestCase):
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
