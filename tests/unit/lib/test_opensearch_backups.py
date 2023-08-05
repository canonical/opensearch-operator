# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import unittest
from unittest.mock import MagicMock, call, patch

from charms.opensearch.v0.constants_charm import S3_RELATION, PeerRelationName
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.opensearch_backups import OpenSearchBackup
from charms.rolling_ops.v0.rollingops import RollingOpsManager
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestOpenSearchBackups(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"
    BASE_CHARM_CLASS = f"{BASE_LIB_PATH}.opensearch_base_charm.OpenSearchBaseCharm"

    @patch("charm.OpenSearchOperatorCharm._put_admin_user")
    def setUp(self, _put_admin_user) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.peer_rel = self.harness.add_relation(PeerRelationName, self.charm.app.name)

        self.secret_store = self.charm.secrets

    @patch.object(OpenSearchBackup, "register_snapshot_repo")
    @patch.object(OpenSearchBackup, "_is_started")
    @patch.object(YamlConfigSetter, "delete")
    @patch.object(RollingOpsManager, "_on_acquire_lock")
    @patch.object(YamlConfigSetter, "put")
    def test_add_remove_relation(
        self,
        mock_yaml_setter_put,
        mock_acquire_lock,
        mock_yaml_setter_delete,
        mock_started,
        mock_register_repo,
    ):
        """Test the add and remove relation and its access to plugin, keystore, config."""
        self.charm.opensearch.add_plugin_without_restart = MagicMock()
        mock_add_plugin = self.charm.opensearch.add_plugin_without_restart
        self.charm.opensearch.add_to_keystore = MagicMock()
        mock_add_ks = self.charm.opensearch.add_to_keystore
        mock_started.return_value = True
        mock_register_repo.return_value = False

        s3_rel = self.harness.add_relation(S3_RELATION, "s3-integrator")
        self.harness.add_relation_unit(s3_rel, "s3-integrator/0")
        self.harness.update_relation_data(
            s3_rel,
            "s3-integrator",
            {
                "bucket": "s3://unit-test",
                "access-key": "aaaa",
                "secret-key": "bbbb",
                "path": "/test",
                "endpoint": "localhost",
                "region": "testing-region",
                "storage-class": "storageclass",
            },
        )
        mock_add_plugin.assert_called_once_with("repository-s3", batch=True)
        mock_acquire_lock.assert_called()
        yaml_setter_put_calls = [
            call("opensearch.yml", "s3.client.default.endpoint", "localhost"),
            call("opensearch.yml", "s3.client.default.region", "testing-region"),
            call("opensearch.yml", "s3.client.default.max_retries", 3),
            call("opensearch.yml", "s3.client.default.path_style_access", False),
            call("opensearch.yml", "s3.client.default.protocol", "https"),
            call("opensearch.yml", "s3.client.default.read_timeout", "50s"),
            call("opensearch.yml", "s3.client.default.use_throttle_retries", True),
        ]
        mock_yaml_setter_put.assert_has_calls(yaml_setter_put_calls)
        mock_add_ks.assert_has_calls(
            [
                call("s3.client.default.access_key", "aaaa", force=True),
                call("s3.client.default.secret_key", "bbbb", force=True),
            ]
        )

        # Now remove the relation
        self.charm.opensearch.remove_plugin_without_restart = MagicMock()
        mock_remove_plugin = self.charm.opensearch.remove_plugin_without_restart
        self.charm.opensearch.remove_from_keystore = MagicMock()
        mock_remove_from_keystore = self.charm.opensearch.remove_from_keystore
        self.harness.remove_relation(s3_rel)
        mock_acquire_lock.assert_called()
        mock_remove_plugin.assert_called_once_with("repository-s3")
        yaml_setter_delete_calls = [
            call("opensearch.yml", "s3.client.default.endpoint"),
            call("opensearch.yml", "s3.client.default.region"),
            call("opensearch.yml", "s3.client.default.max_retries"),
            call("opensearch.yml", "s3.client.default.path_style_access"),
            call("opensearch.yml", "s3.client.default.protocol"),
            call("opensearch.yml", "s3.client.default.read_timeout"),
            call("opensearch.yml", "s3.client.default.use_throttle_retries"),
        ]
        mock_yaml_setter_delete.assert_has_calls(yaml_setter_delete_calls)
        mock_remove_from_keystore.assert_has_calls(
            [
                call("s3.client.default.access_key"),
                call("s3.client.default.secret_key"),
            ]
        )
