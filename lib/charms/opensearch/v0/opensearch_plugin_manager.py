# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import logging
from typing import Dict, List

from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
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
                os_version=self._opensearch.version,
                relation_data=self._charm.model.get_relation(plugin_data["relation-name"]).data
                if plugin_data["relation-name"]
                else None,
            )
            for _, plugin_data in ConfigExposedPlugins.items()
        ]

    def run(self) -> bool:
        """Runs a check on each plugin: install, execute config changes or remove.

        This method should be called at config-changed event. Returns if needed restart.
        """
        return self.install() or self.configure() or self.disable()

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
            if plugin.status == PluginState.MISSING and (
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
                # Call any specifics for post-installation
                plugin.install()
                needs_restart = True
        return needs_restart

    def configure(self) -> bool:
        """Gathers all the configuration changes needed and applies them.

        Returns True if a restart is needed.
        """
        original_config = self._opensearch_config.load_node()
        for plugin in self.plugins:
            if plugin.status != PluginState.AVAILABLE:
                continue
            self._opensearch_config.add_plugin(plugin)
            self._keystore.add(plugin.config()["keystore"])

        new_config = self._opensearch_config.load_node()
        for c in new_config.keys():
            if c not in original_config or new_config[c] != original_config[c]:
                return True
        return False

    def disable(self) -> bool:
        """If enabled, removes plugin configuration or sets it to other values."""
        original_config = self._opensearch_config.load_node()
        for plugin in self.plugins:
            if (
                plugin.status != PluginState.ENABLED
                or plugin.status != PluginState.WAITING_FOR_UPGRADE
            ):
                continue
            self._opensearch_config.delete_plugin(plugin)
            self._keystore.delete(plugin.config()["keystore"])

        new_config = self._opensearch_config.load_node()
        for c in new_config.keys():
            if c not in original_config or new_config[c] != original_config[c]:
                return True
        return False

    def status(self) -> Dict[PluginState, List[str]]:
        """Returns a dict summarizing the status of each plugin.

        It can be converted to str and used in the message status or for logging.
        """
        full_status = {}
        for plugin in self.plugins:
            stat = plugin.status
            if isinstance(full_status[stat], list):
                full_status[stat].append(plugin.name)
            else:
                full_status[stat] = [plugin.name]
        return full_status

    def plugins_need_upgrade(self) -> List[OpenSearchPlugin]:
        """Returns a list of plugins that need upgrade."""
        return [plugin.name for plugin in self.plugins if plugin.needs_upgrade]

    def _is_plugin_relation_set(self, relation_name: str) -> bool:
        """Returns True if a relation is expected and it is set."""
        if not relation_name:
            return True
        return len(self._charm.framework.model.relations[relation_name] or {}) > 0

    def _add_plugin(self, plugin: str) -> bool:
        """Add a plugin to this node. Restart must be managed in separated."""
        try:
            args = f"install --batch {plugin}"
            self._opensearch.run_bin("opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "already exists" in str(e):
                return
            raise OpenSearchPluginError(f"Failed to install plugin {plugin}: " + str(e))

    def _remove_plugin(self, plugin):
        """Remove a plugin without restarting the node."""
        try:
            args = f"remove {plugin}"
            self._opensearch.run_bin("opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "not found" in str(e):
                logger.warn("Plugin {plugin} not found, leaving remove method")
                return
            raise OpenSearchPluginError(f"Failed to remove plugin {plugin}: " + str(e))

    def _list_plugins(self):
        """List plugins."""
        try:
            return list(
                filter(None, self._opensearch.run_bin("opensearch-plugin", "list").split("\n"))
            )
        except OpenSearchCmdError as e:
            raise OpenSearchPluginError("Failed to list plugins: " + str(e))
