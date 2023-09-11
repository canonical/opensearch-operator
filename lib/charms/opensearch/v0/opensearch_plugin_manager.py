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
    OpenSearchPluginInstallError,
    OpenSearchPluginMissingDepsError,
    OpenSearchPluginRemoveError,
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
        restart = False
        # Save original configuration to compare later
        original_config = self._opensearch_config.load_node()
        for plugin in self.plugins:
            restart = self._install(plugin) or restart
            self._configure(plugin)
            self._disable(plugin)

        # Compare configurations, if there was a change, request a restart
        new_config = self._opensearch_config.load_node()
        for c in new_config.keys():
            if c not in original_config or new_config[c] != original_config[c]:
                return True
        # we may need or not a restart
        return restart

    def _install(self, plugin: OpenSearchPlugin) -> bool:
        """Installs all the plugins enabled via the config/relation.

        Check if plugin in status: PluginState.MISSING and config/relation is set.
        Returns True if a restart is needed.
        """
        needs_restart = False
        installed_plugins = self._list_plugins()

        if self.status(plugin) == PluginState.MISSING and self._user_requested_to_enable(plugin):
            # Check for dependencies
            missing_deps = [dep for dep in plugin.dependencies if dep not in installed_plugins]
            if missing_deps:
                raise OpenSearchPluginMissingDepsError(plugin.name, missing_deps)

            # Execute the installation
            self._add_plugin(plugin.name)
            needs_restart = True
        return needs_restart

    def _configure(self, plugin: OpenSearchPlugin) -> None:
        """Gathers all the configuration changes needed and applies them."""
        if not self._user_requested_to_enable(plugin) or self._is_enabled(plugin):
            # Leave this method if either user did not request to enable this plugin
            # or plugin has been already enabled.
            return
        self._opensearch_config.add_plugin(plugin.config()["opensearch"])
        self._keystore.add(plugin.config()["keystore"])

    def _disable(self, plugin: OpenSearchPlugin) -> None:
        """If disabled, removes plugin configuration or sets it to other values."""
        if self.status(plugin) != PluginState.AVAILABLE:
            # Only considering "available" status as it represents a plugin that has
            # been installed but either not yet configured or user explicitly disabled.
            return
        self._opensearch_config.delete_plugin(plugin.config()["opensearch"])
        self._keystore.delete(plugin.config()["keystore"])

    def plugins_need_upgrade(self) -> List[OpenSearchPlugin]:
        """Returns a list of plugins that need upgrade."""
        return [plugin.name for plugin in self.plugins if self._needs_upgrade(plugin)]

    def status(self, plugin: OpenSearchPlugin) -> PluginState:
        """Returns the status for a given plugin."""
        if not self._is_installed(plugin):
            return PluginState.MISSING
        if not self._user_requested_to_enable(plugin) or not self._is_enabled(plugin):
            return PluginState.AVAILABLE
        if self._needs_upgrade(plugin):
            return PluginState.WAITING_FOR_UPGRADE
        return PluginState.ENABLED

    def _is_installed(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin is installed."""
        if plugin.name in self._list_plugins():
            return True
        return False

    def _user_requested_to_enable(self, plugin: OpenSearchPlugin) -> bool:
        """Returns True if user requested plugin to be enabled."""
        plugin_data = ConfigExposedPlugins[plugin.name]
        if not self._charm.config.get(
            plugin_data["config-name"], None
        ) and not self._is_plugin_relation_set(plugin_data["relation-name"]):
            # Customer asked to disable this plugin
            return False
        return True

    def _is_enabled(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin is enabled."""
        # If not requested to be disabled, check if options are configured or not
        os_yaml = self._opensearch_config.get_plugin(plugin.config()["opensearch"])
        for config, param in os_yaml.items():
            if plugin.config()["opensearch"].get(config) != param:
                return False
        return True

    def _needs_upgrade(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin needs upgrade."""
        current_version = plugin.version
        num_points = len(self._opensearch.version.split("."))
        return self._opensearch.version != current_version[:num_points]

    def _is_plugin_relation_set(self, relation_name: str) -> bool:
        """Returns True if a relation is expected and it is set."""
        if not relation_name:
            return True
        return len(self._charm.framework.model.relations[relation_name] or {}) > 0

    def _add_plugin(self, name: str) -> None:
        """Add a plugin to this node. Restart must be managed in separated."""
        try:
            args = f"install --batch {name}"
            self._opensearch.run_bin("opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "already exists" in str(e):
                return
            raise OpenSearchPluginInstallError(name, str(e))

    def _remove_plugin(self, name: str) -> None:
        """Remove a plugin without restarting the node."""
        try:
            args = f"remove {name}"
            self._opensearch.run_bin("opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "not found" in str(e):
                logger.warn("Plugin {name} not found, leaving remove method")
                return
            raise OpenSearchPluginRemoveError(name, str(e))

    def _list_plugins(self) -> List[str]:
        """List plugins."""
        try:
            return list(
                filter(None, self._opensearch.run_bin("opensearch-plugin", "list").split("\n"))
            )
        except OpenSearchCmdError as e:
            raise OpenSearchPluginError("Failed to list plugins: " + str(e))
