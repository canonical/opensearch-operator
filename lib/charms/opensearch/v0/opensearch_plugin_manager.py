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

from charms.opensearch.v0.constants_charm import PluginConfigStart
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.opensearch_backups import OpenSearchBackupPlugin
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_keystore import OpenSearchKeystore
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchKnn,
    OpenSearchPlugin,
    OpenSearchPluginConfig,
    OpenSearchPluginError,
    OpenSearchPluginEventScope,
    OpenSearchPluginInstallError,
    OpenSearchPluginMissingConfigError,
    OpenSearchPluginMissingDepsError,
    OpenSearchPluginRelationClusterNotReadyError,
    OpenSearchPluginRemoveError,
    PluginState,
)
from ops.model import MaintenanceStatus

# The unique Charmhub library identifier, never change it
LIBID = "da838485175f47dbbbb83d76c07cab4c"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


ConfigExposedPlugins = {
    "opensearch-knn": {
        "class": OpenSearchKnn,
        "config": "plugin_opensearch_knn",
        "relation": None,
    },
    "repository-s3": {
        "class": OpenSearchBackupPlugin,
        "config": None,
        "relation": "s3-credentials",
    },
}


class OpenSearchPluginManager:
    """Manages plugins."""

    def __init__(self, charm):
        """Creates the plugin manager object based on the charm and home_path.

        Stores the home path and, optionally, plugins path can also be passed if it is
        not available in {home_path}/plugins.
        """
        self._charm = charm
        self._opensearch = charm.opensearch
        self._opensearch_config = charm.opensearch_config
        self._charm_config = self._charm.model.config
        self._plugins_path = self._opensearch.paths.plugins
        self._keystore = OpenSearchKeystore(self._charm)
        self._event_scope = OpenSearchPluginEventScope.DEFAULT

    def set_event_scope(self, event_scope: OpenSearchPluginEventScope) -> None:
        """Sets the event scope of the plugin manager.

        This method should be called at the start of each event handler.
        """
        self._event_scope = event_scope

    def reset_event_scope(self) -> None:
        """Resets the event scope of the plugin manager to the default value."""
        self._event_scope = OpenSearchPluginEventScope.DEFAULT

    @property
    def plugins(self) -> List[OpenSearchPlugin]:
        """Returns List of installed plugins."""
        plugins_list = []
        for plugin_data in ConfigExposedPlugins.values():
            new_plugin = plugin_data["class"](
                self._plugins_path, extra_config=self._extra_conf(plugin_data)
            )
            plugins_list.append(new_plugin)
        return plugins_list

    def get_plugin(self, plugin_class: OpenSearchPlugin) -> OpenSearchPlugin:
        """Returns a given plugin based on its class."""
        for plugin in self.plugins:
            if isinstance(plugin, plugin_class):
                return plugin
        raise KeyError(f"Plugin manager did not find plugin: {plugin_class}")

    def get_plugin_status(self, plugin_class: OpenSearchPlugin) -> OpenSearchPlugin:
        """Returns a given plugin based on its class."""
        for plugin in self.plugins:
            if isinstance(plugin, plugin_class):
                return self.status(plugin)
        raise KeyError(f"Plugin manager did not find plugin: {plugin_class}")

    def _extra_conf(self, plugin_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Returns the config from the relation data of the target plugin if applies."""
        relation_name = plugin_data.get("relation")
        relation = self._charm.model.get_relation(relation_name) if relation_name else None
        # If the plugin depends on the relation, it must have at least one unit to be considered
        # for enabling. Otherwise, relation.units == 0 means that the plugin has no remote units
        # and the relation may be going away.
        if relation and relation.units:
            return {
                **relation.data[relation.app],
                **self._charm_config,
                "opensearch-version": self._opensearch.version,
            }
        return {**self._charm_config, "opensearch-version": self._opensearch.version}

    def run(self) -> bool:
        """Runs a check on each plugin: install, execute config changes or remove.

        This method should be called at config-changed event. Returns if needed restart.
        """
        if not (self._charm.opensearch.is_started() and self._charm.opensearch.is_node_up()):
            raise OpenSearchPluginRelationClusterNotReadyError()

        if not (
            len(self._charm._get_nodes(True)) == self._charm.app.planned_units()
            and self._charm.health.apply()
            in [
                HealthColors.GREEN,
                HealthColors.YELLOW,
            ]
        ):
            # If the health is not green, then raise a cluster-not-ready error
            # The classes above should then defer their own events in waiting.
            # Defer is important as next steps to configure plugins will involve
            # calls to the APIs of the cluster.
            raise OpenSearchPluginRelationClusterNotReadyError()

        restart_needed = False
        for plugin in self.plugins:
            restart_needed = any(
                [
                    self._install_if_needed(plugin),
                    self._configure_if_needed(plugin),
                    self._disable_if_needed(plugin),
                    self._remove_if_needed(plugin),
                    restart_needed,
                ]
            )
            if restart_needed:
                self._charm.status.set(MaintenanceStatus(PluginConfigStart))

        self._charm.status.clear(PluginConfigStart)
        return restart_needed

    def _install_plugin(self, plugin: OpenSearchPlugin) -> bool:
        """Install a plugin enabled via config/relation.

        Returns True if the plugin was installed.
        """
        installed_plugins = self._installed_plugins()
        if plugin.dependencies:
            missing_deps = [dep for dep in plugin.dependencies if dep not in installed_plugins]
            if missing_deps:
                raise OpenSearchPluginMissingDepsError(
                    f"Failed to install {plugin.name}, missing dependencies: {missing_deps}"
                )

        # Add the plugin
        try:
            if self.status(plugin) != PluginState.MISSING or not self._user_requested_to_enable(
                plugin
            ):
                # Nothing to do here
                return False

            # Check for dependencies
            missing_deps = [dep for dep in plugin.dependencies if dep not in installed_plugins]
            if missing_deps:
                raise OpenSearchPluginMissingDepsError(
                    f"Failed to install {plugin.name}, missing dependencies: {missing_deps}"
                )

            self._opensearch.run_bin("opensearch-plugin", f"install --batch {plugin.name}")
        except KeyError as e:
            raise OpenSearchPluginMissingConfigError(e)
        except OpenSearchCmdError as e:
            if "already exists" in str(e):
                logger.info(f"Plugin {plugin.name} already installed, continuing...")
                # Nothing installed, as plugin already exists
                return False
            raise OpenSearchPluginInstallError(f"Failed to install plugin {plugin.name}: {e}")
        # Install successful
        return True

    def _install_if_needed(self, plugin: OpenSearchPlugin) -> bool:
        """Installs all the plugins enabled via the config/relation.

        Check if plugin in status: PluginState.MISSING and config/relation is set.
        Returns True if the plugin was installed.
        """
        if self.status(plugin) != PluginState.MISSING or not self._user_requested_to_enable(
            plugin
        ):
            # Nothing to do here
            return False

        return self._install_plugin(plugin)

    def _configure_if_needed(self, plugin: OpenSearchPlugin) -> bool:
        """Gathers all the configuration changes needed and applies them."""
        try:
            if (
                not self._user_requested_to_enable(plugin)
                or self.status(plugin) != PluginState.INSTALLED
            ):
                # Leave this method if either user did not request to enable this plugin
                # or plugin has been already enabled.
                return False
            return self.apply_config(plugin.config())
        except KeyError as e:
            raise OpenSearchPluginMissingConfigError(e)

    def _disable_if_needed(self, plugin: OpenSearchPlugin) -> bool:
        """If disabled, removes plugin configuration or sets it to other values."""
        try:
            if self._user_requested_to_enable(plugin) or self.status(plugin) not in [
                PluginState.ENABLED,
                PluginState.WAITING_FOR_UPGRADE,
            ]:
                # Only considering "INSTALLED" or "WAITING FOR UPGRADE" status as it
                # represents a plugin that has been installed but either not yet configured
                # or user explicitly disabled.
                return False
            return self.apply_config(plugin.disable())
        except KeyError as e:
            raise OpenSearchPluginMissingConfigError(e)

    def apply_config(self, config: OpenSearchPluginConfig) -> bool:
        """Runs the configuration changes as passed via OpenSearchPluginConfig.

        For each: configuration and secret
        1) Remove the entries to be deleted
        2) Add entries, if available

        For example:
            KNN needs to:
            1) Remove from configuration: {"knn.plugin.enabled": "True"}
            2) Add to configuration: {"knn.plugin.enabled": "False"}

        Returns True if a configuration change was performed.
        """
        self._keystore.delete(config.secret_entries_to_del)
        self._keystore.add(config.secret_entries_to_add)
        if config.secret_entries_to_del or config.secret_entries_to_add:
            self._keystore.reload_keystore()

        # Add and remove configuration if applies
        current_settings = ClusterTopology.get_cluster_settings(
            self._charm.opensearch,
            include_defaults=True,
        )
        to_remove = config.config_entries_to_del
        if isinstance(config.config_entries_to_del, list):
            # No keys should have value "None", therefore, setting them to None means
            # the original current_settings will be changed.
            to_remove = dict(
                zip(config.config_entries_to_del, [None] * len(config.config_entries_to_del))
            )
        logger.debug(f"apply_config: {current_settings}")

        if current_settings == {
            **current_settings,
            **to_remove,
            **config.config_entries_to_add,
        }:
            # Nothing to do here
            logger.info(
                "apply_config: nothing to do, return"
            )
            return False

        # Update the configuration
        if config.config_entries_to_del:
            self._opensearch_config.delete_plugin(config.config_entries_to_del)
        if config.config_entries_to_add:
            self._opensearch_config.add_plugin(config.config_entries_to_add)
        return True

    def status(self, plugin: OpenSearchPlugin) -> PluginState:
        """Returns the status for a given plugin."""
        if not self._is_installed(plugin):
            return PluginState.MISSING
        if not self._is_enabled(plugin):
            if self._user_requested_to_enable(plugin):
                return PluginState.INSTALLED
            return PluginState.DISABLED
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
        """Returns true if plugin is enabled.

        The main question to answer is if we would remove the configuration from
        opensearch.yaml and/or add some other configuration instead.
        If yes, then we know that the service is enabled.

        The disable() method is used, as a given entry will be removed from opensearch.yml.

        If disable() returns a list, then check if the keys in the stored_plugin_conf
        matches the list values; otherwise, if a dict, then check if the keys and values match.
        If they match in any of the cases above, then return True.
        """
        try:
            plugin_conf = plugin.disable().config_entries_to_del
            keystore_conf = plugin.disable().secret_entries_to_del
            stored_plugin_conf = self._opensearch_config.get_plugin(plugin_conf)

            if any(k not in self._keystore.list() for k in keystore_conf):
                return False

            # Using sets to guarantee matches; stored_plugin_conf will be a dict
            if isinstance(plugin_conf, list):
                return set(plugin_conf) == set(stored_plugin_conf)
            else:  # plugin_conf is a dict
                return plugin_conf == stored_plugin_conf
        except (KeyError, OpenSearchPluginError) as e:
            logger.warning(f"_is_enabled: error with {e}")
            return False

    def _needs_upgrade(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin needs upgrade."""
        plugin_version = plugin.version.split(".")
        version = self._opensearch.version.split(".")
        num_points = min(len(plugin_version), len(version))
        return version[:num_points] != plugin_version[:num_points]

    def _is_plugin_relation_set(self, relation_name: str) -> bool:
        """Returns True if a relation is expected and it is set."""
        if not relation_name:
            return False
        relation = self._charm.model.get_relation(relation_name)
        if self._event_scope == OpenSearchPluginEventScope.RELATION_BROKEN_EVENT:
            return relation is not None and relation.units
        return relation is not None

    def _remove_if_needed(self, plugin: OpenSearchPlugin) -> bool:
        """If disabled, removes plugin configuration or sets it to other values."""
        if self.status(plugin) == PluginState.DISABLED:
            if plugin.REMOVE_ON_DISABLE:
                return self._remove_plugin(plugin)
        return False

    def _remove_plugin(self, plugin: OpenSearchPlugin) -> bool:
        """Remove a plugin without restarting the node."""
        try:
            self._opensearch.run_bin("opensearch-plugin", f"remove {plugin.name}")
        except OpenSearchCmdError as e:
            if "not found" in str(e):
                logger.info(f"Plugin {plugin.name} to be deleted, not found. Continuing...")
                return False
            raise OpenSearchPluginRemoveError(f"Failed to remove plugin {plugin.name}: {e}")
        return True

    def _installed_plugins(self) -> List[str]:
        """List plugins."""
        try:
            return self._opensearch.run_bin("opensearch-plugin", "list").split("\n")
        except OpenSearchCmdError as e:
            raise OpenSearchPluginError("Failed to list plugins: " + str(e))
