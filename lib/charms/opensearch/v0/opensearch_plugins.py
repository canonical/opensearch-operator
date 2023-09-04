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

Optionally, PluginState can also be overridden to add more status.

Add a new configuration in the config.yaml with "plugin_" as prefix to its name.
Add the corresponding config-name to the ConfigExposedPlugins.

If a given plugin depends on a relation, e.g. repository-s3, then add relation name
as well. For example:
    ConfigExposedPlugins = {
        ...
        "opensearch-knn": {
            "class": OpenSearchPlugin,
            "config-name": "plugin_opensearch_knn",
            "relation-name": ""
        },
    }
"""

import logging
import os
from abc import abstractmethod
from typing import Any, Dict, List, Optional

from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.opensearch_exceptions import OpenSearchPluginError
from jproperties import Properties

# The unique Charmhub library identifier, never change it
LIBID = "3b05456c6e304680b4af8e20dae246a2"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class PluginState(BaseStrEnum):
    """Enum for the states possible in plugins' lifecycle."""

    MISSING = "missing"
    AVAILABLE = "available"
    ENABLED = "enabled"
    WAITING_FOR_UPGRADE = "waiting-for-upgrade"


class OpenSearchPlugin:
    """Abstract class describing an OpenSearch plugin."""

    PLUGIN_PROPERTIES = "plugin-descriptor.properties"
    CONFIG_YML = "opensearch.yml"

    def __init__(
        self,
        plugins_path: str,
        os_version: Optional[str] = "",
        relation_data: Optional[Dict[str, Any]] = {},
    ):
        """Creates the OpenSearchPlugin object."""
        self._plugins_path = plugins_path
        self._os_version = os_version
        self._relation_data = relation_data
        self._properties = Properties()
        self._depends_on = []

    @property
    def version(self) -> str:
        """Returns the current version of the plugin."""
        plugin_props_path = os.path.join(f"{self._plugins_path}", f"{self.PLUGIN_PROPERTIES}")
        try:
            with open(plugin_props_path) as f:
                self._properties.load(f.read())
        except FileNotFoundError:
            raise OpenSearchPluginError(f"Plugin is missing - not found: {plugin_props_path}")
        except PermissionError:
            raise OpenSearchPluginError(
                f"Plugin incorrectly installed - permission denied: {plugin_props_path}"
            )
        except Exception:
            raise OpenSearchPluginError("Plugin Error - Unknown reason")
        return self._properties._properties["version"]

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of plugin name dependencies."""
        return self._depends_on

    @abstractmethod
    def install(self) -> Any:
        """Executes any additional steps needed for the installation.

        Should only execute steps that are not covered in PluginManager.
        """
        pass

    @property
    def is_installed(self) -> bool:
        """Check if plugin is installed by checking if plugin properties file exists."""
        try:
            # Consider it is installed if properties file is present and readable.
            _ = self.version
        except Exception:
            return False
        return True

    @abstractmethod
    def configure(self) -> Dict[str, Dict[str, str]]:
        """Returns a dict containing all the configuration needed to be applied in the form.

        Format:
        {
            "opensearch.yml": {...},
            "keystore": {...},
        }
        """
        pass

    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        """Runs any specific steps to check if the plugin is enabled."""
        pass

    def needs_upgrade(self) -> bool:
        """Returns if the plugin needs an upgrade or not.

        Needs upgrade must be set if an upgrade on the charm happens and plugins must
        be updated.

        Consider overriding this method only if the plugin needs an special care at upgrade.
        """
        current_version = self.version
        num_points = len(self._os_version.split("."))
        return self._os_version != current_version[:num_points]

    @abstractmethod
    def upgrade(self, uri: str) -> Any:
        """Runs specific extra steps for upgrade for this plugin."""
        pass

    def disable(self) -> Dict[str, Any]:
        """Returns a dict containing different config changes.

        The dict should return:
        (1) all the configs to remove
        (2) all the configs to add
        (3) all the keystore values to be remmoved.
        """
        return {"to_remove_opensearch": [], "to_add_opensearch": [], "to_remove_keystore": []}

    @property
    def status(self) -> PluginState:
        """Returns the current state of the plugin."""
        if not self.is_installed:
            return PluginState.MISSING
        if not self.is_enabled:
            return PluginState.AVAILABLE
        if self.needs_upgrade:
            return PluginState.WAITING_FOR_UPGRADE
        return PluginState.ENABLED

    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the name of the plugin."""
        pass
