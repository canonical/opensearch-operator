# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import copy
import functools
import logging
from typing import Dict, List, Tuple, Type

from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_keystore import (
    OpenSearchKeystore,
    OpenSearchKeystoreNotReadyYetError,
)
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchBackupPlugin,
    OpenSearchKnn,
    OpenSearchPlugin,
    OpenSearchPluginConfig,
    OpenSearchPluginError,
    OpenSearchPluginInstallError,
    OpenSearchPluginMissingConfigError,
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


ConfigExposedPlugins = {
    "opensearch-knn": {
        "class": OpenSearchKnn,
        "config": "plugin_opensearch_knn",
    },
    "repository-s3": {
        "class": OpenSearchBackupPlugin,
        "config": None,
    },
}


class OpenSearchPluginManagerNotReadyYetError(OpenSearchPluginError):
    """Exception when the plugin manager is not yet prepared."""


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
        self._keystore = OpenSearchKeystore(self._charm)

    @functools.cached_property
    def cluster_config(self):
        """Returns the cluster configuration."""
        return ClusterTopology.get_cluster_settings(self._charm.opensearch, include_defaults=True)

    @functools.cached_property
    def plugins(self) -> List[OpenSearchPlugin]:
        """Returns List of installed plugins."""
        plugins_list = []
        for plugin_data in ConfigExposedPlugins.values():
            new_plugin = plugin_data["class"](self._charm)
            plugins_list.append(new_plugin)
        return plugins_list

    def get_plugin(self, plugin_class: Type[OpenSearchPlugin]) -> OpenSearchPlugin:
        """Returns a given plugin based on its class."""
        for plugin in self.plugins:
            if isinstance(plugin, plugin_class):
                return plugin

        raise KeyError(f"Plugin manager did not find plugin: {plugin_class}")

    def get_plugin_status(self, plugin_class: Type[OpenSearchPlugin]) -> PluginState:
        """Returns a given plugin based on its class."""
        for plugin in self.plugins:
            if isinstance(plugin, plugin_class):
                return self.status(plugin)
        raise KeyError(f"Plugin manager did not find plugin: {plugin_class}")

    def is_ready_for_api(self) -> bool:
        """Checks if the plugin manager is ready to run API calls."""
        return self._charm.health.get() not in [HealthColors.RED, HealthColors.UNKNOWN]

    def run(self) -> bool:
        """Runs a check on each plugin: install, execute config changes or remove.

        This method should be called at config-changed event. Returns if needed restart.
        """
        is_manager_ready = True
        err_msgs = []
        restart_needed = False
        for plugin in self.plugins:
            logger.info(f"Checking plugin {plugin.name}...")
            logger.debug(f"Status: {self.status(plugin)}")
            # These are independent plugins.
            # Any plugin that errors, if that is an OpenSearchPluginError, then
            # it is an "expected" error, such as missing additional config; should
            # not influence the execution of other plugins.
            # Capture them and raise all of them at the end.
            try:
                restart_needed = any(
                    [
                        self._install_if_needed(plugin),
                        self._configure_if_needed(plugin),
                        self._disable_if_needed(plugin),
                        self._remove_if_needed(plugin),
                        restart_needed,
                    ]
                )
            except (
                OpenSearchPluginMissingDepsError,
                OpenSearchPluginMissingConfigError,
                OpenSearchPluginInstallError,
                OpenSearchPluginRemoveError,
            ) as e:
                # This is a more serious issue, as we are missing some input from
                # the user. The charm should block.
                err_msgs.append(str(e))
                logger.debug(f"Finished Plugin {plugin.name}: error '{str(e)}' found")

            except OpenSearchKeystoreNotReadyYetError:
                # Plugin manager must wait until the keystore is to finish its setup.
                # This separated exception allows to separate this error and process
                # it differently, once we have inserted all plugins' configs.

                # Store the error and continue
                # We want to apply all configuration changes to the cluster and then
                # inform the caller this method needs to be reran later to update keystore.
                # The keystore does not demand a restart, so we can process it later.
                is_manager_ready = False
                logger.debug(f"Finished Plugin {plugin.name} waiting for keystore")
            else:
                logger.debug(f"Finished Plugin {plugin.name} status: {self.status(plugin)}")
        logger.info(f"Plugin check finished, restart needed: {restart_needed}")

        if not is_manager_ready:
            # Next run, configurations above will not change, as they have been applied, and
            # only the missing keystore will be set.
            raise OpenSearchKeystoreNotReadyYetError()
        if err_msgs:
            raise OpenSearchPluginError("\n".join(err_msgs))
        return restart_needed

    def _install_plugin(self, plugin: OpenSearchPlugin) -> bool:
        """Install a plugin enabled via config/relation.

        Returns True if the plugin was installed.
        """
        installed_plugins = self._installed_plugins
        if plugin.dependencies:
            missing_deps = [dep for dep in plugin.dependencies if dep not in installed_plugins]
            if missing_deps:
                raise OpenSearchPluginMissingDepsError(plugin.name, missing_deps)

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
                raise OpenSearchPluginMissingDepsError(plugin.name, missing_deps)

            self._opensearch.run_bin("opensearch-plugin", f"install --batch {plugin.name}")
            self._clean_cache_if_needed()
        except KeyError as e:
            raise OpenSearchPluginMissingConfigError(e)
        except OpenSearchCmdError as e:
            if "already exists" in str(e):
                logger.info(f"Plugin {plugin.name} already installed, continuing...")
                # Nothing installed, as plugin already exists
                return False
            raise OpenSearchPluginInstallError(plugin.name)
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
            if self.status(plugin) != PluginState.ENABLING_NEEDED:
                # Leave this method if either user did not request to enable this plugin
                # or plugin has been already enabled.
                return False
            return self.apply_config(plugin.config())
        except KeyError as e:
            raise OpenSearchPluginMissingConfigError(e)

    def _disable_if_needed(self, plugin: OpenSearchPlugin) -> bool:
        """If disabled, removes plugin configuration or sets it to other values."""
        try:
            if self.status(plugin) != PluginState.DISABLING_NEEDED:
                return False
            return self.apply_config(plugin.disable())
        except KeyError as e:
            raise OpenSearchPluginMissingConfigError(e)

    def _compute_settings(
        self, config: OpenSearchPluginConfig
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Returns the current and the new configuration."""
        if not self._charm.opensearch.is_node_up() or not self.is_ready_for_api():
            return None, None

        current_settings = self.cluster_config
        # We use current_settings and new_conf and check for any differences
        # therefore, we need to make a deepcopy here before editing new_conf
        # Also, we simply apply the config.config_entries straight to new_conf
        # As setting a config entry to None will render a "null" entry with
        # jsonl dumps, and hence, it will be removed from the configuration.
        new_conf = copy.deepcopy(current_settings) | config.config_entries

        logger.debug(
            "Difference between current and new configuration: \n"
            + str(
                {
                    "in current but not in new_conf": {
                        k: v for k, v in current_settings.items() if k not in new_conf.keys()
                    },
                    "in new_conf but not in current": {
                        k: v for k, v in new_conf.items() if k not in current_settings.keys()
                    },
                    "in both but different values": {
                        k: v
                        for k, v in new_conf.items()
                        if k in current_settings.keys() and current_settings[k] != v
                    },
                }
            )
        )
        return current_settings, new_conf

    def apply_config(self, config: OpenSearchPluginConfig) -> bool:  # noqa: C901
        """Runs the configuration changes as passed via OpenSearchPluginConfig.

        For each: configuration and secret
        1) Remove the entries to be deleted
        2) Add entries, if available
        Returns True if a configuration change was performed on opensearch.yml only
        and a restart is needed.

        Executes the following steps:
        1) Inserts / removes the entries from opensearch.yml.
        2) Tries to manage the keystore
        3) If settings API is available, tries to manage the configuration there

        Given keystore + settings both use APIs to reload data, restart only happens
        if the configuration files have been changed only.

        Raises:
            OpenSearchKeystoreNotReadyYetError: If the keystore is not yet ready.
        """
        # Update the configuration files
        if config.config_entries:
            self._opensearch_config.update_plugin(config.config_entries)

        settings_changed_via_api = False
        try:
            # If security is not yet initialized, this code will throw an exception
            self._keystore.update(config.secret_entries)
            if config.secret_entries:
                self._keystore.reload_keystore()
        except (OpenSearchKeystoreNotReadyYetError, OpenSearchHttpError):
            # We've failed to set the keystore, we need to rerun this method later
            # Postpone the exception now and set the remaining config.
            raise OpenSearchKeystoreNotReadyYetError()

        try:
            current_settings, new_conf = self._compute_settings(config)
            if current_settings and new_conf and current_settings != new_conf:
                if config.config_entries:
                    # Set the configuration via API or throw an exception
                    # and request a restart otherwise
                    self._opensearch.request(
                        "PUT",
                        "/_cluster/settings?flat_settings=true",
                        payload=f'{{"persistent": {str(config)} }}',
                        retries=3,
                    )
                    settings_changed_via_api = True

            if settings_changed_via_api:
                # We have changed the cluster settings, clean up the cache
                del self.cluster_config

            return False
        except OpenSearchHttpError:
            logger.warning(f"Failed to apply via API configuration for: {config.config_entries}")
            # We only call `apply_config` if we need it, so, in this case, we need a restart
            # If we have any config keys, then we need to restart
            return config.config_entries != {}

    def status(self, plugin: OpenSearchPlugin) -> PluginState:
        """Returns the status for a given plugin."""
        if not self._is_installed(plugin):
            return PluginState.MISSING

        if self._needs_upgrade(plugin):
            return PluginState.WAITING_FOR_UPGRADE

        # The _user_request_to_enable comes first, as it ensures there is a relation/config
        # set, which will be used by _is_enabled to determine if we are enabled or not.
        try:
            if not self._is_enabled(plugin) and not self._user_requested_to_enable(plugin):
                return PluginState.DISABLED
            elif not self._is_enabled(plugin) and self._user_requested_to_enable(plugin):
                return PluginState.ENABLING_NEEDED
            elif self._is_enabled(plugin) and self._user_requested_to_enable(plugin):
                return PluginState.ENABLED
            else:  # self._user_requested_to_enable(plugin) == False
                return PluginState.DISABLING_NEEDED
        except (
            OpenSearchKeystoreNotReadyYetError,
            OpenSearchPluginMissingConfigError,
        ):
            # We are keystore access. Report the plugin is only installed
            pass
        return PluginState.INSTALLED

    def _is_installed(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin is installed."""
        return plugin.name in self._installed_plugins

    def _user_requested_to_enable(self, plugin: OpenSearchPlugin) -> bool:
        """Returns True if user requested plugin to be enabled."""
        return plugin.requested_to_enable()

    def _is_enabled(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin is enabled.

        The main question to answer is if we would have it in the configuration
        from cluster settings. If yes, then we know that the service is enabled.

        Check if the configuration from enable() is present or not.

        Raise:
            OpenSearchKeystoreNotReadyYetError: If the keystore is not yet ready
        """
        # Avoid the keystore check as we may just be writing configuration in the files
        # while the cluster is not up and running yet.
        if plugin.config().secret_entries:
            # Need to check keystore
            # If the keystore is not yet set, then an exception will be raised here
            keys_available = self._keystore.list
            keys_to_add = [
                k
                for k in plugin.config().secret_entries.keys()
                if plugin.config().secret_entries.get(k)
            ]
            if any(k not in keys_available for k in keys_to_add):
                return False
            keys_to_del = [
                k
                for k in plugin.config().secret_entries.keys()
                if not plugin.config().secret_entries.get(k)
            ]
            if any(k in keys_available for k in keys_to_del):
                return False

        # We always check the configuration files, as we always persist data there
        existing_setup = self._opensearch_config.get_plugin(plugin.config().config_entries)

        if any([k not in existing_setup.keys() for k in plugin.config().config_entries.keys()]):
            return False

        # Now, we know the keys are there, we must check their values
        return all(
            [
                plugin.config().config_entries[k] == existing_setup[k]
                for k in plugin.config().config_entries.keys()
            ]
        )

    def _needs_upgrade(self, plugin: OpenSearchPlugin) -> bool:
        """Returns true if plugin needs upgrade."""
        plugin_version = plugin.version.split(".")
        version = self._opensearch.version.split(".")
        num_points = min(len(plugin_version), len(version))
        return version[:num_points] != plugin_version[:num_points]

    def _remove_if_needed(self, plugin: OpenSearchPlugin) -> bool:
        """If disabled, removes plugin configuration or sets it to other values."""
        return False

    def _remove_plugin(self, plugin: OpenSearchPlugin) -> bool:
        """Remove a plugin without restarting the node."""
        try:
            self._opensearch.run_bin("opensearch-plugin", f"remove {plugin.name}")
            self._clean_cache_if_needed()

        except OpenSearchCmdError as e:
            if "not found" in str(e):
                logger.info(f"Plugin {plugin.name} to be deleted, not found. Continuing...")
                return False
            raise OpenSearchPluginRemoveError(plugin.name)
        return True

    def _clean_cache_if_needed(self):
        if self.plugins:
            del self.plugins
        if self._installed_plugins:
            del self._installed_plugins

    @functools.cached_property
    def _installed_plugins(self) -> List[str]:
        """List plugins."""
        try:
            return self._opensearch.run_bin("opensearch-plugin", "list").split("\n")
        except OpenSearchCmdError as e:
            raise OpenSearchPluginError("Failed to list plugins: " + str(e))
