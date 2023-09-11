# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
import unittest
from unittest.mock import MagicMock, PropertyMock, call, patch

import charms
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchPlugin,
    OpenSearchPluginError,
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
"""


class TestPlugin(OpenSearchPlugin):
    """Overrides the OpenSearchPlugin and returns a is_enabled=True always."""

    __test__ = False

    test_plugin_disable_called = False
    PLUGIN_PROPERTIES = "test_plugin.properties"

    def __init__(self, plugins_path):
        super().__init__(plugins_path)
        self._depends_on = ["test-plugin-dependency"]

    @property
    def name(self):
        return "test"

    def config(self):
        return {}

    def disable(self) -> bool:
        """This method is not used."""
        raise NotImplementedError

    def upgrade(self, _: str) -> None:
        """Runs the upgrade process in this plugin."""
        raise NotImplementedError


class TestPluginAlreadyInstalled(TestPlugin):
    """Overrides the OpenSearchPlugin and returns a is_enabled=True always."""

    __test__ = False

    test_plugin_disable_called = False
    PLUGIN_PROPERTIES = "test_plugin.properties"

    def __init__(self, plugins_path):
        super().__init__(plugins_path)

    def config(self):
        return {self.CONFIG_YML: {"param": "tested"}, "keystore": {"key1": "secret1"}}


class TestOpenSearchPlugin(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm
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
                "config-name": "plugin_test",
                "relation-name": None,
            },
        }

    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager.is_enabled")
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager.is_installed")
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    def test_install_plugin_and_check_status(
        self, mock_load, mock_version, mock_is_installed, mock_is_enabled
    ) -> None:
        """Reconfigure the plugin at main configuration file."""
        mock_version.return_value = "2.8.0"
        mock_is_installed.return_value = True
        mock_is_enabled.return_value = True
        test_plugin = self.plugin_manager.plugins[0]
        assert test_plugin.version == "2.9.0.0"
        assert self.plugin_manager.status(test_plugin) == PluginState.WAITING_FOR_UPGRADE

    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    def test_failed_install_plugin(self, _, mock_version) -> None:
        """Tests a failed command."""
        mock_version.return_value = "2.8.0"
        succeeded = False
        self.charm.opensearch._run_cmd = MagicMock(
            side_effect=OpenSearchCmdError("this is a test")
        )
        self.plugin_manager._list_plugins = MagicMock(return_value=["test-plugin-dependency"])
        try:
            self.plugin_manager.install()
        except OpenSearchPluginError as e:
            assert str(e) == "Failed to install plugin test: this is a test"
            succeeded = True
        finally:
            # We may reach this point because of another exception, check it:
            assert succeeded is True

    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    def test_failed_install_plugin_already_exists(self, _, mock_version) -> None:
        """Tests a failed command when the plugin already exists."""
        mock_version.return_value = "2.8.0"
        succeeded = True
        self.charm.opensearch._run_cmd = MagicMock(
            side_effect=OpenSearchCmdError("this is a test - already exists")
        )
        self.plugin_manager._list_plugins = MagicMock(return_value=["test-plugin-dependency"])
        try:
            self.plugin_manager.install()
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
        mock_version.return_value = "2.8.0"
        succeeded = False
        self.charm.opensearch._run_cmd = MagicMock(return_value=RETURN_LIST_PLUGINS)
        try:
            self.plugin_manager.install()
        except OpenSearchPluginError as e:
            assert (
                str(e)
                == "Failed to install test, missing dependencies: ['test-plugin-dependency']"
            )
            succeeded = True
        # Check if we had any other exception
        assert succeeded is True

    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    def test_check_manager_if_plugins_need_upgrade(
        self, _, mock_request, mock_load, mock_version
    ) -> None:
        """Validates the plugin manager when checking for an upgrade."""
        mock_version.return_value = "2.8.0"
        mock_request.return_value = {"version": {"number": "3.0"}}
        mock_load.return_value = {}
        assert self.plugin_manager.plugins_need_upgrade() == ["test"]

    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._list_plugins")
    @patch(
        "charms.opensearch.v0.opensearch_keystore.OpenSearchKeystore.exists",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version")
    # Test the integration between opensearch_config and plugin
    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
    def test_reconfigure_add_keystore_plugin(
        self, mock_put, mock_version, mock_load, mock_exists, mock_list_plugins
    ) -> None:
        """Reconfigure the keystore only.

        Should not trigger restart, hence return False in the config() method.
        """
        mock_version.return_value = "2.8.0"
        mock_exists.return_value = True
        config = {"param": "tested"}
        mock_put.return_value = config
        self.plugin_manager._keystore._add = MagicMock()
        self.plugin_manager._opensearch.request = MagicMock(return_value={"status": 200})
        # Override the ConfigExposedPlugins with another class type
        charms.opensearch.v0.opensearch_plugin_manager.ConfigExposedPlugins = {
            "test": {
                "class": TestPluginAlreadyInstalled,
                "config-name": "plugin_test",
                "relation-name": None,
            },
        }
        # Mock _list_plugins to return test
        mock_list_plugins.return_value = ["test"]

        mock_load.side_effect = [{}, {}, {"param": "tested"}]
        self.assertTrue(self.plugin_manager.configure())
        self.plugin_manager._keystore._add.assert_has_calls([call("key1", "secret1")])
        self.charm.opensearch.config.put.assert_has_calls(
            [call(self.charm.opensearch_config.CONFIG_YML, "param", "tested")]
        )
        self.plugin_manager._opensearch.request.assert_has_calls(
            [call("POST", "_nodes/reload_secure_settings")]
        )

    @patch(
        "charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._is_plugin_relation_set"
    )
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._list_plugins")
    @patch(
        "charms.opensearch.v0.opensearch_keystore.OpenSearchKeystore.exists",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version")
    # Test the integration between opensearch_config and plugin
    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    def test_plugin_setup_with_relation(
        self,
        _,
        mock_put,
        mock_version,
        mock_load,
        mock_exists,
        mock_list_plugins,
        mock_plugin_relation,
    ) -> None:
        """Triggers a config change and should call plugin manager."""
        mock_version.return_value = "2.8.0"
        mock_exists.return_value = True
        config = {"param": "tested"}
        mock_put.return_value = config
        self.plugin_manager._keystore._add = MagicMock()
        self.plugin_manager._opensearch.request = MagicMock(return_value={"status": 200})
        # Override the ConfigExposedPlugins with another class type
        charms.opensearch.v0.opensearch_plugin_manager.ConfigExposedPlugins = {
            "test": {
                "class": TestPluginAlreadyInstalled,
                "config-name": None,
                "relation-name": "test-relation",
            },
        }
        # Mock _list_plugins to return test
        mock_list_plugins.return_value = ["test"]

        self.charm.model.get_relation = MagicMock()
        mock_load.side_effect = [{}, {}, {"param": "tested"}]
        mock_plugin_relation.return_value = True
        self.assertTrue(self.plugin_manager.configure())
        self.plugin_manager._keystore._add.assert_has_calls([call("key1", "secret1")])
        self.charm.opensearch.config.put.assert_has_calls(
            [call(self.charm.opensearch_config.CONFIG_YML, "param", "tested")]
        )
        mock_plugin_relation.assert_called_once()
        self.plugin_manager._opensearch.request.assert_has_calls(
            [call("POST", "_nodes/reload_secure_settings")]
        )

    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
    )
    def test_check_plugin_called_on_config_changed(self, mock_version) -> None:
        """Triggers a config change and should call plugin manager."""
        mock_version.return_value = "2.8.0"
        self.plugin_manager.run = MagicMock(return_value=False)
        self.charm.opensearch_config.update_host_if_needed = MagicMock(return_value=False)
        self.charm.opensearch.is_started = MagicMock(return_value=True)
        self.harness.update_config({})
        self.plugin_manager.run.assert_called()
