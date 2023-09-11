# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import logging
from typing import List

from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchPlugin,
    OpenSearchPluginError,
    PluginState,
)

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
    """Manages plugins."""

    CONFIG_YML = "opensearch.yml"

    def __init__(self, charm, plugins_path: str = None):
        """Creates the plugin manager object based on the charm and home_path.

        Stores the home path and, optionally, plugins path can also be passed if it is
        not available in {home_path}/plugins.
        """
        self._charm = charm
        self._opensearch = charm.opensearch
        self._opensearch_config = charm.opensearch_config
        self._charm_config = self._charm.framework.model.config
        self._plugins_path = plugins_path
        self._keystore = charm.opensearch_keystore

    @property
    def plugins(self) -> List[OpenSearchPlugin]:
        """Returns List of installed plugins."""
        return [
            plugin_data["class"](
                self._plugins_path,
            )
            for _, plugin_data in ConfigExposedPlugins.items()
        ]

    def run(self) -> bool:
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
        for plugin in self.plugins:
            plugin_data = ConfigExposedPlugins[plugin.name]
            config_name = plugin_data["config-name"]
            relation_name = plugin_data["relation-name"]
            if self.status(plugin) == PluginState.MISSING and (
                (config_name and self._charm_config[config_name])
                or self._is_plugin_relation_set(relation_name)
            ):
                # Check for dependencies
                missing_deps = [dep for dep in plugin.dependencies if dep not in installed_plugins]
                if missing_deps:
                    raise OpenSearchPluginError(
                        f"Failed to install {plugin.name}, missing dependencies: {missing_deps}"
                    )
                # Execute the installation
                self._add_plugin(plugin.name)
                needs_restart = True
        return needs_restart

    def configure(self) -> bool:
        """Gathers all the configuration changes needed and applies them.

        Returns True if a restart is needed.
        """
        original_config = self._opensearch_config.load_node()
        for plugin in self.plugins:
            if self.status(plugin) != PluginState.AVAILABLE:
                continue
            self._opensearch_config.add_plugin(plugin)
            self._keystore.add(plugin.config()["keystore"])

        new_config = self._opensearch_config.load_node()
        for c in new_config.keys():
            if c not in original_config or new_config[c] != original_config[c]:
                return True
        return False

    def disable(self) -> bool:
        """If disabled, removes plugin configuration or sets it to other values."""
        original_config = self._opensearch_config.load_node()
        for plugin in self.plugins:
            # Disable if customer requests
            if self.is_enabled(plugin):
                # Customer did not ask to disable it OR there is no configuration
                # applied to openserch.yaml config
                continue
            self._opensearch_config.delete_plugin(plugin)
            self._keystore.delete(plugin.config()["keystore"])

        new_config = self._opensearch_config.load_node()
        for c in new_config.keys():
            if c not in original_config or new_config[c] != original_config[c]:
                return True
        return False

    def status(self, plugin: OpenSearchPlugin) -> PluginState:
        """Returns the status for a given plugin."""
        if not self.is_installed(plugin):
            return PluginState.MISSING
        if not self.is_enabled(plugin):
            return PluginState.AVAILABLE
        if self.needs_upgrade(plugin):
            return PluginState.WAITING_FOR_UPGRADE
        return PluginState.ENABLED

    def is_installed(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin is installed."""
        if plugin.name in self._list_plugins():
            return True
        return False

    def is_enabled(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin is enabled."""
        # First, check if customer asked to disable the plugin
        plugin_data = ConfigExposedPlugins[plugin.name]
        if not self._charm.config.get(
            plugin_data["config-name"], None
        ) and not self._is_plugin_relation_set(plugin_data["relation-name"]):
            # Customer asked to disable this plugin
            return False

        # If not requested to be disabled, check if options are configured or not
        for config, param in self._opensearch_config.get_plugin(plugin).items():
            if plugin.config()[self.CONFIG_YML].get(config) != param:
                return False
        return True

    def needs_upgrade(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin needs upgrade."""
        current_version = plugin.version
        num_points = len(self._opensearch.version.split("."))
        return self._opensearch.version != current_version[:num_points]

    def plugins_need_upgrade(self) -> List[OpenSearchPlugin]:
        """Returns a list of plugins that need upgrade."""
        return [plugin.name for plugin in self.plugins if self.needs_upgrade(plugin)]

    def _is_plugin_relation_set(self, relation_name: str) -> bool:
        """Returns True if a relation is expected and it is set."""
        if not relation_name:
            return True
        return len(self._charm.framework.model.relations[relation_name] or {}) > 0

    def _add_plugin(self, plugin: str) -> None:
        """Add a plugin to this node. Restart must be managed in separated."""
        try:
            args = f"install --batch {plugin}"
            self._opensearch.run_bin("opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "already exists" in str(e):
                return
            raise OpenSearchPluginError(f"Failed to install plugin {plugin}: " + str(e))

    def _remove_plugin(self, plugin: str) -> None:
        """Remove a plugin without restarting the node."""
        try:
            args = f"remove {plugin}"
            self._opensearch.run_bin("opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "not found" in str(e):
                logger.warn("Plugin {plugin} not found, leaving remove method")
                return
            raise OpenSearchPluginError(f"Failed to remove plugin {plugin}: " + str(e))

    def _list_plugins(self) -> List[str]:
        """List plugins."""
        try:
            return list(
                filter(None, self._opensearch.run_bin("opensearch-plugin", "list").split("\n"))
            )
        except OpenSearchCmdError as e:
            raise OpenSearchPluginError("Failed to list plugins: " + str(e))
