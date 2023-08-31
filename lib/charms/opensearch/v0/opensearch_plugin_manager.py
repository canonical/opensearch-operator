# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This class will manage each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import logging
import os
from typing import Dict, List

from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchKeystoreError,
    OpenSearchPluginError,
)
from charms.opensearch.v0.opensearch_plugins import OpenSearchPlugin, PluginState

# The unique Charmhub library identifier, never change it
LIBID = "da838485175f47dbbbb83d76c07cab4c"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


ConfigExposedPlugins = {}


class OpenSearchPluginManager:
    """Manages the currently plugins."""

    CONFIG_YML = "opensearch.yml"

    def __init__(self, charm, plugins_path: str = None):
        """Creates the plugin manager object based on the charm and home_path.

        Stores the home path and, optionally, plugins path can also be passed if it is
        not available in {home_path}/plugins.
        """
        self._conf_path = charm.opensearch.paths.conf
        self._charm = charm
        self._distro = charm.opensearch
        self._config = charm.opensearch_config
        self._charm_config = self._charm.framework.model.config
        self._plugins_path = plugins_path or os.path.join(f"{self._conf_path}", "plugins/")

    @property
    def plugins(self) -> Dict[str, OpenSearchPlugin]:
        """Returns dict of installed plugins."""
        return {
            key: plugin_data["class"](key, self)
            for key, plugin_data in ConfigExposedPlugins.items()
        }

    def on_config_change(self) -> bool:
        """Runs a check on each plugin: install, execute config changes or remove.

        This method should be called at config-changed event. Returns if needed restart.
        """
        return any([self.install(), self.configure(), self.disable()])

    def install(self) -> bool:
        """Installs all the plugins enabled via the config/relation.

        Check if plugin in status: PluginState.MISSING and config/relation is set.
        Returns True if a restart is needed.
        """
        needs_restart = False
        installed_plugins = self._list_plugins()
        for plugin_name, plugin in self.plugins.items():
            plugin_data = ConfigExposedPlugins[plugin_name]
            config_name = plugin_data["config-name"]
            relation_name = plugin_data["relation-name"]
            if plugin.status == PluginState.MISSING and (
                (config_name and self._charm_config[config_name])
                or self._is_plugin_relation_set(relation_name)
            ):
                # Check for dependencies
                missing_deps = [dep for dep in plugin.dependencies if dep not in installed_plugins]
                if missing_deps:
                    raise OpenSearchPluginError(
                        f"Failed to install {plugin_name}, missing dependencies: {missing_deps}"
                    )
                # Execute the installation
                self._add_plugin(plugin_name)
                # Call any specifics for post-installation
                plugin.install()
                needs_restart = True
        return needs_restart

    def configure(self) -> bool:
        """Gathers all the configuration changes needed and applies them."""
        configs = {self.CONFIG_YML: {}, "keystore": {}}
        for plugin in self.plugins.values():
            if plugin.status != PluginState.AVAILABLE:
                continue
            c = plugin.configure()
            # Merge the dict, where in case of conflict, the plugin.configure() keys get
            # the priority
            configs[self.CONFIG_YML] = {**configs[self.CONFIG_YML], **c[self.CONFIG_YML]}
            configs["keystore"] = {**configs["keystore"], **c["keystore"]}

        self._update_keystore_and_reload(configs["keystore"])
        return self._config.config_put_list(configs[self.CONFIG_YML])

    def disable(self) -> bool:
        """If enabled, removes plugin configuration or sets it to other values."""
        configs = {"to_remove_opensearch": [], "to_add_opensearch": [], "to_remove_keystore": []}
        for plugin in self.plugins.values():
            if (
                plugin.status != PluginState.ENABLED
                or plugin.status != PluginState.WAITING_FOR_UPGRADE
            ):
                continue
            c = plugin.disable()
            for key in c.keys():
                configs[key] += c[key]

        self._update_keystore_and_reload(configs["to_remove_keystore"], remove_keys=True)
        needs_restart = self._config.config_delete_list(configs["to_remove_opensearch"])
        return self._config.config_put_list(configs["to_add_opensearch"]) or needs_restart

    def status(self) -> Dict[PluginState, List[str]]:
        """Returns a dict summarizing the status of each plugin.

        It can be converted to str and used in the message status or for logging.
        """
        full_status = {}
        for plugin_name, plugin in self.plugins.items():
            stat = plugin.status
            if isinstance(full_status[stat], list):
                full_status[stat].append(plugin_name)
            else:
                full_status[stat] = [plugin_name]
        return full_status

    def plugins_need_upgrade(self) -> List[OpenSearchPlugin]:
        """Returns a list of plugins that need upgrade."""
        return [
            name for name, obj in self.plugins.items() if obj.needs_upgrade(self._distro.version)
        ]

    def _is_plugin_relation_set(self, relation_name: str) -> bool:
        """Returns True if a relation is expected and it is set."""
        if not relation_name:
            return True
        return len(self.charm.framework.model.relations[relation_name] or {}) > 0

    def _update_keystore_and_reload(
        self, keystore: Dict[str, str], remove_keys: bool = False
    ) -> None:
        """Updates the keystore value (adding or removing) and reload."""
        if not keystore:
            return
        try:
            for key, value in keystore.items():
                if remove_keys:
                    self._remove_from_keystore(key)
                else:
                    self._add_to_keystore(key, value)
            # Now, reload the security settings and return if opensearch needs restart
            post = self._distro.request("POST", "_nodes/reload_secure_settings")
            logger.debug(f"_update_keystore_and_reload: response received {post}")
        except OpenSearchKeystoreError as ek:
            raise ek
        except Exception as e:
            logger.exception(e)
            raise OpenSearchPluginError("Unknown error during keystore reload")
        if post["status"] < 200 or post["status"] >= 300:
            raise OpenSearchPluginError("Error while processing _nodes reload")

    def _add_plugin(self, plugin: str) -> bool:
        """Add a plugin to this node. Restart must be managed in separated."""
        try:
            args = f"install --batch {plugin}"
            self._distro.run_bin("opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "already exists" in str(e):
                return
            raise OpenSearchPluginError(f"Failed to install plugin {plugin}: " + str(e))

    def _remove_plugin(self, plugin):
        """Remove a plugin without restarting the node."""
        try:
            args = f"remove {plugin}"
            self._distro.run_bin("opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "not found" in str(e):
                logger.warn("Plugin {plugin} not found, leaving remove method")
                return
            raise OpenSearchPluginError(f"Failed to remove plugin {plugin}: " + str(e))

    def _list_plugins(self):
        """List plugins."""
        try:
            return self._distro.run_bin("opensearch-plugin", "list").split("\n")
        except OpenSearchCmdError as e:
            raise OpenSearchPluginError("Failed to list plugins: " + str(e))

    def _add_to_keystore(self, key: str, value: str):
        """Adds a given key to the "opensearch" keystore."""
        if not value:
            raise OpenSearchKeystoreError("Missing keystore value")
        args = f"add --force {key}"
        try:
            # Add newline to the end of the key, if missing
            v = value + ("" if value[-1] == "\n" else "\n")
            self._distro.run_bin("opensearch-keystore", args, input=v)
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    def _remove_from_keystore(self, key: str):
        """Removes a given key from "opensearch" keystore."""
        args = f"remove {key}"
        try:
            self._distro.run_bin("opensearch-keystore", args)
        except OpenSearchCmdError as e:
            if "does not exist in the keystore" in str(e):
                return
            raise OpenSearchKeystoreError(str(e))
