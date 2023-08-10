# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
import os
import unittest
from unittest.mock import MagicMock, call, patch

from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchPlugin,
    PluginPropertiesSetter,
    SecurityPolicySetter,
)
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


class TestSecurityPolicySetter(unittest.TestCase):
    def setUp(self) -> None:
        self.secpol = SecurityPolicySetter("tests/unit/resources/")
        self.security_policy = self.secpol.load("test_security_policy")

    def test_load(self):
        """Test loading a policy file and serializing it into a dict."""
        self.assertEqual(len(self.security_policy.keys()), 6)
        data_check = {
            "java.lang.RuntimePermission": {"accessDeclaredMembers": [], "getClassLoader": []},
            "java.lang.reflect.ReflectPermission": {"suppressAccessChecks": []},
            "java.net.SocketPermission": {"*": ["connect"]},
            "java.net.NetPermission": {"setDefaultAuthenticator": []},
            "java.util.PropertyPermission": {
                "opensearch.allow_insecure_settings": ["read,write"],
                "aws.sharedCredentialsFile": ["read,write"],
                "aws.configFile": ["read,write"],
                "opensearch.path.conf": ["read,write"],
            },
            "java.io.FilePermission": {"config": ["read"]},
        }
        for key, d in data_check.items():
            assert key in self.security_policy.keys()
            for k, v in d.items():
                self.assertEqual(v, self.security_policy[key][k])

    def test_put_insert(self):
        """Test the insert on a file."""
        input_file = "test_security_policy"
        output_file = "test_security_policy_produced"

        self.secpol.put(
            input_file,
            "java.util.PropertyPermission/aws.configFile",
            "newval",
            output_file=output_file,
        )
        self.secpol.put(output_file, "test/test", "newval", output_file=output_file)
        self.assertEqual(
            self.secpol.load(output_file)["java.util.PropertyPermission"]["aws.configFile"],
            ["read,write", "newval"],
        )
        self.assertEqual(self.secpol.load(output_file)["test"]["test"], ["newval"])

    def test_del_remove(self):
        """Test the remove on a file."""
        input_file = "test_security_policy"
        output_file = "test_security_policy_produced"

        self.secpol.delete(
            input_file, "java.util.PropertyPermission/aws.configFile", output_file=output_file
        )
        self.secpol.delete(output_file, "java.net.NetPermission", output_file=output_file)
        self.assertTrue(
            "aws.configFile" not in self.secpol.load(output_file)["java.util.PropertyPermission"]
        )
        self.assertTrue("java.net.NetPermission" not in self.secpol.load(output_file))

    def tearDown(self) -> None:
        output = "tests/unit/resources/test_security_policy_produced"
        if os.path.exists(output):
            os.remove("tests/unit/resources/test_security_policy_produced")


class TestPluginPropertiesSetter(unittest.TestCase):
    def setUp(self) -> None:
        self.plugin = PluginPropertiesSetter("tests/unit/resources/")
        self.props = self.plugin.load("test_plugin.properties")

    def test_properties_load(self):
        """Test loading a policy file and serializing it into a dict."""
        self.assertEqual(len(self.props.keys()), 8)
        data_check = {
            "description": ["OpenSearch k-NN plugin"],
            "version": ["2.9.0.0"],
            "name": ["opensearch-knn"],
            "classname": ["org.opensearch.knn.plugin.KNNPlugin"],
            "java.version": ["11"],
            "opensearch.version": ["2.9.0"],
            "custom.foldername": [],
            "extended.plugins": ["lang-painless"],
        }
        for key, d in data_check.items():
            self.assertEqual(d, self.props[key])

    def test_properties_put_insert(self):
        """Test the insert on a file."""
        input_file = "test_plugin.properties"
        output_file = "test_plugin_properties_produced"

        self.plugin.put(input_file, "description", "newval", output_file=output_file)
        self.plugin.put(output_file, "test", "newval", output_file=output_file)
        self.assertEqual(self.plugin.load(output_file)["description"], ["newval"])
        self.assertEqual(self.plugin.load(output_file)["test"], ["newval"])

    def test_properties_del_remove(self):
        """Test the remove on a file."""
        input_file = "test_plugin.properties"
        output_file = "test_plugin_properties_produced"

        self.plugin.delete(input_file, "description", output_file=output_file)
        self.assertTrue("description" not in self.plugin.load(output_file))
        self.plugin.delete(output_file, "custom.foldername", output_file=output_file)
        self.assertTrue("custom.foldername" not in self.plugin.load(output_file))

    def tearDown(self) -> None:
        output = "tests/unit/resources/test_plugin_properties_produced"
        if os.path.exists(output):
            os.remove("tests/unit/resources/test_plugin_properties_produced")
