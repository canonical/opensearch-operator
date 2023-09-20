# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import logging
from typing import Any, Dict, List, Optional

from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchPlugin,
    OpenSearchPluginApplyConfigError,
    OpenSearchPluginConfig,
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
        self._charm_config = self._charm.model.config
        self._plugins_path = plugins_path
        self._keystore = charm.opensearch_keystore

    @property
    def plugins(self) -> List[OpenSearchPlugin]:
        """Returns List of installed plugins."""
        plugin_list = []
        for plugin_data in ConfigExposedPlugins.values():
            new_plugin = plugin_data["class"](
                self._plugins_path, extra_config=self._extra_conf(plugin_data)
            )
            plugin_list += [new_plugin]
        return plugin_list

    def _extra_conf(self, plugin_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Returns either the config or relation data for the target plugin."""
        relation_name = plugin_data.get("relation")
        relation = self._charm.model.get_relation(relation_name) if relation_name else None
        if not relation:
            return None
        return relation.data[self._charm.app]

    def run(self) -> bool:
        """Runs a check on each plugin: install, execute config changes or remove.

        This method should be called at config-changed event. Returns if needed restart.
        """
        restart_needed = False
        for plugin in self.plugins:
            restart_needed = any(
                [
                    self._install_if_needed(plugin),
                    self._configure_if_needed(plugin),
                    self._disable_if_needed(plugin),
                    restart_needed,
                ]
            )
        return restart_needed

    def _install_if_needed(self, plugin: OpenSearchPlugin) -> bool:
        """Installs all the plugins enabled via the config/relation.

        Check if plugin in status: PluginState.MISSING and config/relation is set.
        Returns True if a restart is needed.
        """
        installed_plugins = self._installed_plugins()

        if self.status(plugin) == PluginState.MISSING and self._user_requested_to_enable(plugin):
            # Check for dependencies
            missing_deps = list(
                filter(lambda dep: dep not in installed_plugins, plugin.dependencies)
            )
            if missing_deps:
                raise OpenSearchPluginMissingDepsError(
                    f"Failed to install {plugin.name}, missing dependencies: {missing_deps}"
                )

            # Add the plugin
            try:
                self._opensearch.run_bin("opensearch-plugin", f"install --batch {plugin.name}")
            except OpenSearchCmdError as e:
                if "already exists" in str(e):
                    logger.info(
                        "opensearch_plugin_manager._add_plugin:"
                        f" Plugin {plugin.name} already exists, continuing..."
                    )
                    return
                raise OpenSearchPluginInstallError(f"Failed to install plugin {plugin.name}: {e}")
            return True

        # Nothing was installed
        return False

    def _configure_if_needed(self, plugin: OpenSearchPlugin) -> bool:
        """Gathers all the configuration changes needed and applies them."""
        if not self._user_requested_to_enable(plugin) or self._is_enabled(plugin):
            # Leave this method if either user did not request to enable this plugin
            # or plugin has been already enabled.
            return False
        return self._apply_config(plugin.config())

    def _disable_if_needed(self, plugin: OpenSearchPlugin) -> bool:
        """If disabled, removes plugin configuration or sets it to other values."""
        if self.status(plugin) != PluginState.INSTALLED:
            # Only considering "INSTALLED" status as it represents a plugin that has
            # been installed but either not yet configured or user explicitly disabled.
            return False
        return self._apply_config(plugin.disable())

    def _apply_config(self, config: OpenSearchPluginConfig) -> bool:
        """Runs the configuration changed as passed via OpenSearchPluginConfig.

        For each: configuration and secret
        1) Remove the entries to be deleted in each one
        2) Add entries, if available

        For example:
            KNN needs to:
            1) Remove from configuration: {"knn.plugin.enabled": "True"}
            2) Add to configuration: {"knn.plugin.enabled": "False"}

        Returns True if restart is needed.
        """
        self._keystore.delete(config.secret_entries_to_del)
        self._keystore.add(config.secret_entries_to_add)
        # Add and remove configuration, return True if a reboot is needed
        if config.config_entries_to_del and not self._opensearch_config.delete_plugin(
            config.config_entries_to_del
        ):
            # There is configuration to remove and it failed
            raise OpenSearchPluginApplyConfigError(
                f"Failed removing configuration: {config.config_entries_to_del}"
            )
        if config.config_entries_to_add and not self._opensearch_config.add_plugin(
            config.config_entries_to_add
        ):
            # There is configuration to add and it failed
            raise OpenSearchPluginApplyConfigError(
                f"Failed adding configuration: {config.config_entries_to_del}"
            )

        # Return True only if we actually had some configuration changed
        return True if config.config_entries_to_add or config.config_entries_to_del else False

    def status(self, plugin: OpenSearchPlugin) -> PluginState:
        """Returns the status for a given plugin."""
        if not self._is_installed(plugin):
            return PluginState.MISSING
        if not self._user_requested_to_enable(plugin) or not self._is_enabled(plugin):
            return PluginState.INSTALLED
        if self._needs_upgrade(plugin):
            return PluginState.WAITING_FOR_UPGRADE
        return PluginState.ENABLED

    def _is_installed(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin is installed."""
        return plugin.name in self._installed_plugins()

    def _user_requested_to_enable(self, plugin: OpenSearchPlugin) -> bool:
        """Returns True if user requested plugin to be enabled."""
        plugin_data = ConfigExposedPlugins[plugin.name]
        if not self._charm.config.get(
            plugin_data["config"], False
        ) and not self._is_plugin_relation_set(plugin_data["relation"]):
            # User asked to disable this plugin
            return False
        return True

    def _is_enabled(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin is enabled."""
        # If not requested to be disabled, check if options are configured or not
        are_configs_enabled = plugin.config().config_entries_to_add
        stored_plugin_conf = self._opensearch_config.get_plugin(are_configs_enabled)
        for key, val in stored_plugin_conf.items():
            if are_configs_enabled.get(key) != val:
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
            return False
        return len(self._charm.framework.model.relations[relation_name] or {}) > 0

    def _remove_plugin(self, name: str) -> None:
        """Remove a plugin without restarting the node."""
        try:
            self._opensearch.run_bin("opensearch-plugin", f"remove {name}")
        except OpenSearchCmdError as e:
            if "not found" in str(e):
                logger.warn(
                    "opensearch_plugin_manager._remove_plugin:"
                    " Plugin {name} not found, leaving remove method"
                )
                return
            raise OpenSearchPluginRemoveError(f"Failed to remove plugin {name}: {e}")

    def _installed_plugins(self) -> List[str]:
        """List plugins."""
        try:
            return list(
                filter(None, self._opensearch.run_bin("opensearch-plugin", "list").split("\n"))
            )
        except OpenSearchCmdError as e:
            raise OpenSearchPluginError("Failed to list plugins: " + str(e))
