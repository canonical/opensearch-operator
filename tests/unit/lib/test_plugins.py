# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
import unittest
from unittest.mock import MagicMock, call, patch

from charms.opensearch.v0.opensearch_plugins import OpenSearchPlugin
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestPlugin(OpenSearchPlugin):
    """Overrides the OpenSearchPlugin and returns a is_enabled=True always."""

    test_plugin_disable_called = False

    def __init__(self, name, charm):
        super().__init__(name, charm, None)

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
        """This method is not used."""
        raise NotImplementedError


def _replace_dict():
    ret = {
        "test": {
            "class": TestPlugin,
            "config-name": "plugin_test",
            "relation-name": None,
        }
    }
    return ret.items()


class TestOpenSearchPlugin(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchPluginsAvailable")
    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
    def test_reconfigure_plugin(self, mock_put, mock_plugins) -> None:
        """Reconfigure the plugin at main configuration file."""
        mock_plugins.items.side_effect = _replace_dict

        config = {"param": "tested"}
        mock_put.return_value = config
        test_plugin = self.charm.opensearch.plugins["test"]

        self.assertTrue(test_plugin.configure(opensearch_yml=config))
        self.charm.opensearch.config.put.assert_has_calls(
            [call(test_plugin.CONFIG_YML, "param", "tested")]
        )

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchPluginsAvailable")
    def test_reconfigure_add_keystore_plugin(self, mock_plugins) -> None:
        """Reconfigure the keystore only.

        Should not trigger restart, hence return False in the configure() method.
        """
        mock_plugins.items.side_effect = _replace_dict
        test_plugin = self.charm.opensearch.plugins["test"]

        mock_plugins.items.side_effect = _replace_dict
        test_plugin.distro.add_to_keystore = MagicMock()
        test_plugin._request = MagicMock()
        test_plugin._request.return_value = {"status": 200}

        self.assertFalse(test_plugin.configure(opensearch_yml={}, keystore={"key1": "secret1"}))
        self.charm.opensearch.add_to_keystore.assert_has_calls(
            [call("key1", "secret1", force=True)]
        )
        test_plugin._request.assert_has_calls([call("POST", "_nodes/reload_secure_settings")])

    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchPluginsAvailable")
    def test_check_plugin_updated_after_config(self, mock_plugins) -> None:
        """Reconfigure the keystore only.

        Should not trigger restart, hence return False in the configure() method.
        """
        mock_plugins.items.side_effect = _replace_dict

        self.charm.opensearch_config.update_host_if_needed = MagicMock()
        self.charm.opensearch_config.update_host_if_needed.return_value = False
        self.charm.model._config = {
            "plugin_test": False,
            "ignore_this_setting": False,
        }
        self.assertTrue(self.charm.opensearch_config.check_charmconfig_if_plugins_updated())
