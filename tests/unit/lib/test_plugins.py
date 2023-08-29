# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
import unittest
from unittest.mock import MagicMock, call, patch

import charms
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchPluginError,
)
from charms.opensearch.v0.opensearch_plugins import OpenSearchPlugin
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestPlugin(OpenSearchPlugin):
    """Overrides the OpenSearchPlugin and returns a is_enabled=True always."""

    test_plugin_disable_called = False
    PLUGIN_PROPERTIES = "test_plugin.properties"

    def __init__(self, name, charm, relname=None):
        super().__init__(name, charm, None)
        self._depends_on = ["test-plugin-dependency"]

    def is_enabled(self) -> bool:
        return True

    def disable(self) -> bool:
        return True

    def upgrade(self, _: str) -> None:
        """Runs the upgrade process in this plugin."""
        raise NotImplementedError

    def enable(self) -> bool:
        """This method is not used."""
        raise NotImplementedError

    def depends_on(self):
        """Returns a list of pseudo-dependencies."""
        return self._depends_on

    def _is_started(self):
        return True


class TestOpenSearchPlugin(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm
        # Override the plugins folder path
        self.charm.opensearch.paths.plugins = "tests/unit/resources"
        self.plugin_manager = self.charm.opensearch._plugin_manager
        # Override the OpenSearchPluginsAvailable
        charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginsAvailable = {
            "test": {
                "class": TestPlugin,
                "config-name": "plugin_test",
                "relation-name": None,
            }
        }

    def test_install_plugin_and_check_version(self) -> None:
        """Reconfigure the plugin at main configuration file."""
        test_plugin = self.plugin_manager.plugins["test"]
        assert test_plugin.version == "2.9.0.0"

    def test_failed_install_plugin(self) -> None:
        """Tests a failed command."""
        succeeded = False
        self.charm.opensearch._run_cmd = MagicMock(
            side_effect=OpenSearchCmdError(returncode=100, stderr="this is a test")
        )
        self.charm.opensearch.list_plugins = MagicMock(return_value=["test-plugin-dependency"])
        try:
            test_plugin = self.plugin_manager.plugins["test"]
            test_plugin.install(uri="test")
        except OpenSearchPluginError as e:
            assert (
                str(e)
                == "Failed to install plugin test: Command error, code: 100, stderr: this is a test"
            )
            succeeded = True
        finally:
            # We may reach this point because of another exception, check it:
            assert succeeded is True

    def test_failed_install_plugin_already_exists(self) -> None:
        """Tests a failed command when the plugin already exists."""
        succeeded = True
        self.charm.opensearch._run_cmd = MagicMock(
            side_effect=OpenSearchCmdError(
                returncode=101, stderr="this is a test - already exists"
            )
        )
        self.charm.opensearch.list_plugins = MagicMock(return_value=["test-plugin-dependency"])
        try:
            test_plugin = self.plugin_manager.plugins["test"]
            test_plugin.install(uri="test")
        except Exception:
            # We are interested on any exception
            succeeded = False
        # Check if we had any exception
        assert succeeded is True

    def test_failed_install_plugin_missing_dependency(self) -> None:
        """Tests a failed install plugin because of missing dependency."""
        succeeded = False
        self.charm.opensearch.list_plugins = MagicMock(return_value=[])
        try:
            test_plugin = self.plugin_manager.plugins["test"]
            test_plugin.install(uri="test")
        except OpenSearchPluginError as e:
            assert (
                str(e)
                == "Failed to install test, missing dependencies: ['test-plugin-dependency']"
            )
            succeeded = True
        # Check if we had any other exception
        assert succeeded is True

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.request")
    def test_check_manager_if_plugins_need_upgrade(self, mock_request) -> None:
        """Validates the plugin manager when checking for an upgrade."""
        mock_request.return_value = {"version": {"number": "3.0"}}
        assert self.plugin_manager.plugins_need_upgrade() == ["test"]

    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
    def test_reconfigure_plugin(self, mock_put) -> None:
        """Reconfigure the plugin at main configuration file."""
        config = {"param": "tested"}
        mock_put.return_value = config
        test_plugin = self.plugin_manager.plugins["test"]

        self.assertTrue(test_plugin.configure(opensearch_yml=config))
        self.charm.opensearch.config.put.assert_has_calls(
            [call(test_plugin.CONFIG_YML, "param", "tested")]
        )

    # Test the integration between opensearch_config and plugin

    def test_reconfigure_add_keystore_plugin(self) -> None:
        """Reconfigure the keystore only.

        Should not trigger restart, hence return False in the configure() method.
        """
        test_plugin = self.plugin_manager.plugins["test"]

        test_plugin.distro.add_to_keystore = MagicMock()
        test_plugin._request = MagicMock()
        test_plugin._request.return_value = {"status": 200}

        self.assertFalse(test_plugin.configure(opensearch_yml={}, keystore={"key1": "secret1"}))
        self.charm.opensearch.add_to_keystore.assert_has_calls(
            [call("key1", "secret1", force=True)]
        )
        test_plugin._request.assert_has_calls([call("POST", "_nodes/reload_secure_settings")])

    def test_check_plugin_updated_after_config(self) -> None:
        """Reconfigure the keystore only.

        Should not trigger restart, hence return False in the configure() method.
        """
        self.charm.opensearch_config.update_host_if_needed = MagicMock()
        self.charm.opensearch_config.update_host_if_needed.return_value = False
        self.charm.model._config = {
            "plugin_test": False,
            "ignore_this_setting": False,
        }
        self.assertTrue(self.charm.opensearch_config.update_plugin_conf_if_needed())
