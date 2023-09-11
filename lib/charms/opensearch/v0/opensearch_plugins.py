# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Plugin model.

In OpenSearch, plugins are also called interchangeably as extensions and modules.

A plugin configuration footprint is composed of:
* Jar files installed in one of the
  ${OPENSEARCH_HOME}/plugins
  ${OPENSEARCH_HOME}/modules
* Configuration passed to the main opensearch.yml, must be removed at plugin removal
* Secrets stored in the keystore
* The file: plugin.properties
* And the security policy in: security.policy
* Other plugins which it depends upon

One last piece of the configuration is any index data uploaded to the cluster using
OpenSearch APIs. That last bit of data must be done by inherinting the OpenSearchPlugin
class and implementing the necessary extra logic.


This file implements abstract methods and data that are common to every plugin during
its lifecycle, including methods to manage configuration files, main processes (install,
upgrade, uninstall, etc).

The plugin lifecycle runs through the following steps:

MISSING (not installed yet) > AVAILABLE (plugin installed, but not configured yet) >
ENABLED (configuration has been applied) > WAITING_FOR_UPGRADE (if an upgrade is needed)
> ENABLED (back to enabled state once upgrade has been applied)

The meaning of each step is, as follows:
* install: installs the plugin JAR files
* is_installed: the installation happened correctly and the JAR files are set
* configure: sets all the necessary configuration for the plugin
* is_enabled: all the configurations have been applied and restart is done, if needed
* needs_upgrade: once the main OpenSearch is upgraded, the plugin needs to check if an
                 upgrade is also needed or not.
* upgrade: run the necessary actions to upgrade the plugin

========================================================================================

                             STEPS TO ADD A NEW PLUGIN

========================================================================================


For a new plugin, add the plugin to the list of "ConfigExposedPlugins" available
in opensearch_plugin_manager.py and override the abstract OpenSearchPlugin.

Add a new configuration in the config.yaml with "plugin_" as prefix to its name.
Add the corresponding config to the ConfigExposedPlugins.

If a given plugin depends on a relation, e.g. repository-s3, then add relation name
as well. For example:
    ConfigExposedPlugins = {
        ...
        "opensearch-knn": {
            "class": OpenSearchPlugin,
            "config": "plugin_opensearch_knn",
            "relation": ""
        },
    }
"""

import logging
import os
from abc import abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.opensearch_exceptions import OpenSearchError
from jproperties import Properties

# The unique Charmhub library identifier, never change it
LIBID = "3b05456c6e304680b4af8e20dae246a2"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OpenSearchPluginError(OpenSearchError):
    """Exception thrown when an opensearch plugin is invalid."""


class OpenSearchPluginMissingDepsError(OpenSearchPluginError):
    """Exception thrown when an opensearch plugin misses installed dependencies."""

    def __init__(self, name: str, missing_dependencies: List[str]):
        self._deps = missing_dependencies
        self._name = name

    def __str__(self):
        """Converts exception to a string."""
        return f"Failed to install {self._name}, missing dependencies: {self._deps}"


class OpenSearchPluginInstallError(OpenSearchPluginError):
    """Exception thrown when opensearch plugin installation fails."""

    def __init__(self, name: str, msg: str):
        self._msg = msg
        self._name = name

    def __str__(self):
        """Converts exception to a string."""
        return f"Failed to install plugin {self._name}: {self._msg}"


class OpenSearchPluginRemoveError(OpenSearchPluginError):
    """Exception thrown when opensearch plugin removal fails."""

    def __init__(self, name: str, msg: str):
        self._msg = msg
        self._name = name

    def __str__(self):
        """Converts exception to a string."""
        return f"Failed to remove plugin {self._name}: {self._msg}"


class PluginState(BaseStrEnum):
    """Enum for the states possible in plugins' lifecycle."""

    MISSING = "missing"
    AVAILABLE = "available"
    ENABLED = "enabled"
    WAITING_FOR_UPGRADE = "waiting-for-upgrade"


class OpenSearchPluginConfig:
    """Represents the default configuration for a plugin."""

    def __init__(
        self,
        config_entries: Optional[Dict[str, Any]] = None,
        secret_entries: Optional[Dict[str, str]] = None,
    ):
        self.config_entries = config_entries
        self.secret_entries = secret_entries


class OpenSearchPlugin:
    """Abstract class describing an OpenSearch plugin."""

    PLUGIN_PROPERTIES = "plugin-descriptor.properties"

    def __init__(self, plugins_path: str):
        """Creates the OpenSearchPlugin object.

        Arguments:
          plugins_path: str, path to the plugins folder
        """
        self._plugins_path = plugins_path
        self._properties = Properties()

    @property
    def version(self) -> str:
        """Returns the current version of the plugin.

        Returns: str, string with the version code for this plugin
        Raises:
            FileNotFoundError: if plugin file is not present
            PermissionError: if plugin file is present, but not set with correct permissions
        """
        plugin_props_path = os.path.join(f"{self._plugins_path}", f"{self.PLUGIN_PROPERTIES}")
        with open(plugin_props_path) as f:
            self._properties.load(f.read())
        return self._properties._properties["version"]

    @property
    @abstractmethod
    def dependencies(self) -> List[str]:
        """Returns a list of plugin name dependencies."""
        pass

    @abstractmethod
    def config(self) -> OpenSearchPluginConfig:
        """Returns a dict containing all the configuration needed to be applied in the form.

        Format:
        OpenSearchPluginConfig(
            self.config_entries = {...},
            self.secret_entries = {...},
        )
        """
        pass

    def disable(self) -> Tuple[OpenSearchPluginConfig, OpenSearchPluginConfig]:
        """Returns a tuple composed of configs that should be removed and ones to add.

        The tuple is formatted as follows
        (<Configuration to be removed>, <Configuration to be added>)
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the plugin."""
        pass
