# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
import unittest
from unittest.mock import MagicMock, PropertyMock, call, patch

import charms
from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.opensearch_backups import OpenSearchBackupPlugin
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchPlugin,
    OpenSearchPluginConfig,
    OpenSearchPluginInstallError,
    OpenSearchPluginMissingConfigError,
    OpenSearchPluginMissingDepsError,
    PluginState,
)
from ops.testing import Harness

from charm import OpenSearchOperatorCharm

RETURN_LIST_PLUGINS = """opensearch-alerting
opensearch-anomaly-detection
opensearch-asynchronous-search
opensearch-cross-cluster-replication
opensearch-geospatial
opensearch-index-management
opensearch-job-scheduler
opensearch-knn
opensearch-ml
opensearch-notifications
opensearch-notifications-core
opensearch-observability
opensearch-performance-analyzer
opensearch-reports-scheduler
opensearch-security
opensearch-sql
prometheus-exporter
"""


class TestPlugin(OpenSearchPlugin):
    """Overrides the OpenSearchPlugin and returns a is_enabled=True always."""

    __test__ = False

    test_plugin_disable_called = False
    PLUGIN_PROPERTIES = "test_plugin.properties"

    def __init__(self, plugins_path, extra_config):
        super().__init__(plugins_path, extra_config)

    @property
    def name(self):
        return "test"

    def config(self):
        return OpenSearchPluginConfig()

    def upgrade(self, _: str) -> None:
        """Runs the upgrade process in this plugin."""
        raise NotImplementedError

    @property
    def dependencies(self):
        return ["test-plugin-dependency"]

    def disable(self):
        return OpenSearchPluginConfig()


class TestPluginAlreadyInstalled(TestPlugin):
    """Overrides the OpenSearchPlugin and returns a is_enabled=True always."""

    __test__ = False

    test_plugin_disable_called = False
    PLUGIN_PROPERTIES = "test_plugin.properties"

    def __init__(self, plugins_path, extra_config):
        super().__init__(plugins_path, extra_config)

    def config(self):
        return OpenSearchPluginConfig(
            config_entries_to_add={"param": "tested"},
            secret_entries_to_add={"key1": "secret1"},
        )

    def disable(self):
        return OpenSearchPluginConfig(
            config_entries_to_del=["param"],
            secret_entries_to_del=["key1"],
        )


class TestOpenSearchPlugin(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"

    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm

        self.peers_data = self.charm.peers_data
        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)

        # Override the config to simulate the TestPlugin
        # As config.yaml does not exist, the setup below simulates it
        self.harness.model._config = {"plugin_test": True, "plugin_test_already_installed": False}
        self.charm.plugin_manager._charm_config = self.harness.model._config
        # Override the plugins folder path
        self.charm.opensearch.paths.plugins = "tests/unit/resources"
        self.plugin_manager = self.charm.plugin_manager
        self.plugin_manager._plugins_path = self.charm.opensearch.paths.plugins
        # Override the ConfigExposedPlugins
        charms.opensearch.v0.opensearch_plugin_manager.ConfigExposedPlugins = {
            "test": {
                "class": TestPlugin,
                "config": "plugin_test",
                "relation": None,
            },
        }
        self.charm.opensearch.is_started = MagicMock(return_value=True)
        self.charm.health.apply = MagicMock(return_value=HealthColors.GREEN)
        self.charm.opensearch.version = "2.9.0"
        self.plugin_manager._is_cluster_ready = MagicMock(return_value=True)

    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._is_enabled")
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._is_installed")
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    def test_plugin_process_plugin_properties_file(
        self, _, mock_version, mock_is_installed, mock_is_enabled
    ) -> None:
        """Reconfigure the plugin at main configuration file."""
        mock_version.return_value = "2.8.0"
        mock_is_installed.return_value = True
        mock_is_enabled.return_value = True
        test_plugin = self.plugin_manager.plugins[0]
        # This check will parse the plugin-properties file present in tests/unit/resources
        assert test_plugin.version == "2.9.0.0"
        assert self.plugin_manager.status(test_plugin) == PluginState.WAITING_FOR_UPGRADE

    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    def test_failed_install_plugin(self, _) -> None:
        """Tests a failed command."""
        succeeded = False
        self.charm.opensearch._run_cmd = MagicMock(
            side_effect=OpenSearchCmdError("this is a test")
        )
        self.plugin_manager._installed_plugins = MagicMock(return_value=["test-plugin-dependency"])
        try:
            test_plugin = self.plugin_manager.plugins[0]
            self.plugin_manager._install_if_needed(test_plugin)
        except OpenSearchPluginInstallError as e:
            assert str(e) == "test"
            succeeded = True
        finally:
            # We may reach this point because of another exception, check it:
            assert succeeded is True

    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    def test_failed_install_plugin_already_exists(self, _) -> None:
        """Tests a failed command when the plugin already exists."""
        succeeded = True
        self.charm.opensearch._run_cmd = MagicMock(
            side_effect=OpenSearchCmdError("this is a test - already exists")
        )
        self.plugin_manager._installed_plugins = MagicMock(return_value=["test-plugin-dependency"])
        try:
            test_plugin = self.plugin_manager.plugins[0]
            self.plugin_manager._install_if_needed(test_plugin)
        except Exception:
            # We are interested on any exception
            succeeded = False
        # Check if we had any exception
        assert succeeded is True

    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    def test_failed_install_plugin_missing_dependency(self, _, mock_version) -> None:
        """Tests a failed install plugin because of missing dependency."""
        succeeded = False
        self.charm.opensearch._run_cmd = MagicMock(return_value=RETURN_LIST_PLUGINS)
        try:
            test_plugin = self.plugin_manager.plugins[0]
            self.plugin_manager._install_if_needed(test_plugin)
        except OpenSearchPluginMissingDepsError as e:
            assert str(e) == "('test', ['test-plugin-dependency'])"
            succeeded = True
        # Check if we had any other exception
        assert succeeded is True

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
    )
    def test_check_plugin_called_on_config_changed(self, mock_version, deployment_desc) -> None:
        """Triggers a config change and should call plugin manager."""
        self.harness.set_leader(True)
        self.peers_data.put(Scope.APP, "security_index_initialised", True)
        self.harness.set_leader(False)

        deployment_desc.return_value = "something"
        self.plugin_manager.run = MagicMock(return_value=False)
        self.charm.opensearch_config.update_host_if_needed = MagicMock(return_value=False)
        self.charm.opensearch.is_started = MagicMock(return_value=True)
        self.plugin_manager.check_plugin_manager_ready_for_api = MagicMock(return_value=True)
        self.harness.update_config({})
        self.plugin_manager.run.assert_called()

    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager.status")
    @patch(
        "charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._installed_plugins"
    )
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version")
    # Test the integration between opensearch_config and plugin
    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
    def test_reconfigure_and_add_keystore_plugin(
        self, mock_put, _, mock_load, mock_installed_plugins, mock_status
    ) -> None:
        """Reconfigure the opensearch.yaml and keystore.

        Should trigger a restart and, hence, run() must return True.
        """
        config = {"param": "tested"}
        mock_put.return_value = config
        mock_status.return_value = PluginState.INSTALLED
        self.plugin_manager._keystore._add = MagicMock()
        self.plugin_manager._opensearch.request = MagicMock(return_value={"status": 200})
        # Override the ConfigExposedPlugins with another class type
        charms.opensearch.v0.opensearch_plugin_manager.ConfigExposedPlugins = {
            "test": {
                "class": TestPluginAlreadyInstalled,
                "config": "plugin_test",
                "relation": None,
            },
        }
        # Mock _installed_plugins to return test
        mock_installed_plugins.return_value = ["test"]

        self.charm._get_nodes = MagicMock(
            return_value={
                "1": {},
                "2": {},
                "3": {},
            }
        )
        self.charm.app.planned_units = MagicMock(return_value=3)
        self.charm.opensearch.is_node_up = MagicMock(return_value=True)

        mock_load.return_value = {}
        # run is called, but only _configure method really matter:
        # Set install to false, so only _configure is evaluated
        self.plugin_manager._install_if_needed = MagicMock(return_value=False)
        self.plugin_manager._disable_if_needed = MagicMock(return_value=False)
        self.assertTrue(self.plugin_manager.run())
        self.plugin_manager._keystore._add.assert_has_calls([call("key1", "secret1")])
        self.charm.opensearch.config.put.assert_has_calls(
            [call("opensearch.yml", "param", "tested")]
        )
        self.plugin_manager._opensearch.request.assert_has_calls(
            [call("POST", "_nodes/reload_secure_settings")]
        )

    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._is_enabled")
    @patch(
        "charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._is_plugin_relation_set"
    )
    @patch(
        "charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._installed_plugins"
    )
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._extra_conf")
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version")
    # Test the integration between opensearch_config and plugin
    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
    def test_plugin_setup_with_relation(
        self,
        mock_put,
        _,
        mock_load,
        mock_process_relation,
        mock_installed_plugins,
        mock_plugin_relation,
        mock_is_enabled,
    ) -> None:
        """Tests end-to-end the feature.

        Mock _is_plugin_relation_set=True and will execute every step of run() method.
        The plugin is considered installed, but not enabled. Therefore, _installed_plugins must
        return the plugin name in its list; whereas _is_enabled is set to False.
        """
        # As there is no real plugin, mock the config option
        config = {"param": "tested"}
        mock_put.return_value = config

        # Return a fake content of the relation
        mock_process_relation.return_value = {"param": "tested"}

        self.charm._get_nodes = MagicMock(
            return_value={
                "1": {},
                "2": {},
                "3": {},
            }
        )
        self.charm.app.planned_units = MagicMock(return_value=3)
        self.charm.opensearch.is_node_up = MagicMock(return_value=True)

        # Keystore-related mocks
        self.plugin_manager._keystore._add = MagicMock()
        self.plugin_manager._opensearch.request = MagicMock(return_value={"status": 200})

        # Override the ConfigExposedPlugins with another class type
        charms.opensearch.v0.opensearch_plugin_manager.ConfigExposedPlugins = {
            "test": {
                "class": TestPluginAlreadyInstalled,
                "config": None,
                "relation": "test-relation",
            },
        }
        # Mock _installed_plugins to return test
        mock_installed_plugins.return_value = ["test"]

        # load_node will be called multiple times
        mock_load.side_effect = [{}, {"param": "tested"}]
        mock_plugin_relation.return_value = True
        # plugin is initially disabled and enabled when method self._disable calls self.status
        mock_is_enabled.side_effect = [
            False,  # called by logger
            False,  # called by self.status, in self._install
            False,  # called by self._configure
            True,  # called by self.status, in self._disable
            True,  # called by logger
        ]
        charms.opensearch.v0.opensearch_plugin_manager.logger = MagicMock()
        self.assertTrue(self.plugin_manager.run())
        self.plugin_manager._keystore._add.assert_has_calls([call("key1", "secret1")])
        self.charm.opensearch.config.put.assert_has_calls(
            [call("opensearch.yml", "param", "tested")]
        )
        mock_plugin_relation.assert_called_with("test-relation")
        self.plugin_manager._opensearch.request.assert_has_calls(
            [call("POST", "_nodes/reload_secure_settings")]
        )

    @patch("charms.opensearch.v0.opensearch_plugin_manager.ClusterTopology.get_cluster_settings")
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._extra_conf")
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._is_enabled")
    @patch(
        "charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._is_plugin_relation_set"
    )
    @patch(
        "charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._installed_plugins"
    )
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version")
    def test_disable_plugin(
        self,
        _,
        mock_installed_plugins,
        mock_plugin_relation,
        mock_is_enabled,
        __,
        mock_get_cluster_settings,
    ) -> None:
        """Tests end-to-end the disable of a plugin."""
        # Keystore-related mocks
        self.plugin_manager._keystore._add = MagicMock()
        self.plugin_manager._keystore._delete = MagicMock()
        self.plugin_manager._opensearch_config.delete_plugin = MagicMock()
        self.plugin_manager._opensearch.request = MagicMock(return_value={"status": 200})

        # Override the ConfigExposedPlugins with another class type
        charms.opensearch.v0.opensearch_plugin_manager.ConfigExposedPlugins = {
            "test": {
                "class": TestPluginAlreadyInstalled,
                "config": None,
                "relation": "test-relation",
            },
        }
        # Mock _installed_plugins to return test
        mock_installed_plugins.return_value = ["test"]

        self.charm._get_nodes = MagicMock(
            return_value={
                "1": {},
                "2": {},
                "3": {},
            }
        )
        self.charm.app.planned_units = MagicMock(return_value=3)
        self.charm.opensearch.is_node_up = MagicMock(return_value=True)

        mock_get_cluster_settings.return_value = {"param": "tested"}
        mock_plugin_relation.return_value = False
        # plugin is initially disabled and enabled when method self._disable calls self.status
        mock_is_enabled.return_value = True

        self.assertTrue(self.plugin_manager.run())
        self.plugin_manager._keystore._add.assert_not_called()
        self.plugin_manager._keystore._delete.assert_called()
        self.plugin_manager._opensearch_config.delete_plugin.assert_has_calls([call(["param"])])


class TestOpenSearchBackupPlugin(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm
        self.charm.opensearch.paths.plugins = "tests/unit/resources"
        self.plugin_manager = self.charm.plugin_manager
        self.plugin_manager._plugins_path = self.charm.opensearch.paths.plugins

    def test_name(self):
        plugin = OpenSearchBackupPlugin(
            plugins_path=self.plugin_manager._plugins_path,
            extra_config={},
        )
        assert plugin.name == "repository-s3"

    def test_config_missing_all_configs(self):
        plugin = OpenSearchBackupPlugin(
            plugins_path=self.plugin_manager._plugins_path,
            extra_config={},
        )
        try:
            plugin.config()
        except OpenSearchPluginMissingConfigError as e:
            assert str(e) == "Plugin repository-s3 missing: ['access-key', 'secret-key']"
        else:
            assert False

    def test_config_with_valid_keys(self):
        plugin = OpenSearchBackupPlugin(
            plugins_path=self.plugin_manager._plugins_path,
            extra_config={},
        )
        plugin._extra_config = {
            "access-key": "ACCESS_KEY",
            "secret-key": "SECRET_KEY",
        }
        expected_config = OpenSearchPluginConfig(
            secret_entries_to_add={
                "s3.client.default.access_key": "ACCESS_KEY",
                "s3.client.default.secret_key": "SECRET_KEY",
            },
        )
        self.assertEqual(plugin.config().__dict__, expected_config.__dict__)

    def test_disable(self):
        plugin = OpenSearchBackupPlugin(
            plugins_path=self.plugin_manager._plugins_path,
            extra_config={},
        )
        expected_config = OpenSearchPluginConfig(
            secret_entries_to_del=[
                "s3.client.default.access_key",
                "s3.client.default.secret_key",
            ],
        )
        self.assertEqual(plugin.disable().__dict__, expected_config.__dict__)
