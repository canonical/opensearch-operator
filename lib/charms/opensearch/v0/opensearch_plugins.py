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

INSTALL > is_installed > is_enabled > needs_upgrade > upgrade > UNINSTALL

The meaning of each step is, as follows:
* is_installed: the installation happened correctly and the JAR files are set
* is_enabled: all the configurations have been applied and restart is done, if needed
* needs_upgrade: once the main OpenSearch is upgraded, the plugin needs to check if an
                 upgrade is also needed or not.
* upgrade: run the necessary actions to upgrade the plugin

========================================================================================

                             STEPS TO ADD A NEW PLUGIN

========================================================================================


For a new plugin, add the plugin to the list of "OpenSearchPluginsAvailable" below and
override the abstract OpenSearchPlugin.

Add a new configuration in the config.yaml with "plugin_" as prefix to its name.
Add the corresponding config-name to the OpenSearchPluginsAvailable.

If a given plugin depends on a relation, e.g. repository-s3, then add relation name
as well. For example:
    OpenSearchPluginsAvailable = {
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
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Union

from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchKeystoreError,
    OpenSearchPluginError,
)
from jproperties import Properties
from ops.framework import Object
from ops.model import ActiveStatus, BlockedStatus, StatusBase

# The unique Charmhub library identifier, never change it
LIBID = "3b05456c6e304680b4af8e20dae246a2"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


OpenSearchPluginsAvailable = {}


class OpenSearchPlugin(ABC):
    """Abstract class describing an OpenSearch plugin."""

    PLUGIN_PROPERTIES = "plugin-descriptor.properties"
    CONFIG_YML = "opensearch.yml"

    def __init__(self, name: str, charm: Object, relname: Optional[str] = None):
        """Creates the OpenSearchPlugin object.

        The *args enable children classes to pass relations.
        """
        self.relname = relname
        self.charm = charm
        self.distro = self.charm.opensearch
        self.CONFIG_YML = self.charm.opensearch_config.CONFIG_YML
        self._name = name
        self._plugin_properties = Properties()

    @property
    def version(self) -> str:
        """Returns the current version of the plugin."""
        with open(os.path.join(f"{self.distro.paths.plugins}", f"{self.PLUGIN_PROPERTIES}")) as f:
            self._plugin_properties.load(f.read())
        return self._plugin_properties._properties["version"]

    def _is_started(self) -> bool:
        return self.distro.is_started()

    def _request(self, *args, **kwargs) -> dict:
        return self.distro.request(*args, **kwargs)

    def is_related(self) -> bool:
        """Returns True if a relation is expected and it is set."""
        if not self.relname:
            return True
        return len(self.charm.framework.model.relations[self.relname] or {}) > 0

    def _update_keystore_and_reload(
        self, keystore: Dict[str, str], force: bool = True, remove_keys: bool = False
    ) -> None:
        if not keystore:
            return
        try:
            for key, value in keystore.items():
                if remove_keys:
                    self.distro.remove_from_keystore(key)
                else:
                    self.distro.add_to_keystore(key, value, force=force)
            # Now, reload the security settings and return if opensearch needs restart
            post = self._request("POST", "_nodes/reload_secure_settings")
            logger.debug(f"_update_keystore_and_reload: response received {post}")
        except OpenSearchKeystoreError as ek:
            raise ek
        except Exception as e:
            logger.exception(e)
            raise OpenSearchPluginError("Unknown error during keystore reload")
        if post["status"] < 200 or post["status"] >= 300:
            raise OpenSearchPluginError("Error while processing _nodes reload")

    @property
    def name(self) -> str:
        """Returns the name of the plugin."""
        return self._name

    def uninstall(
        self,
        opensearch_yml: Dict[str, str],
        keystore: Dict[str, str],
    ) -> bool:
        """Erases relevant data for this plugin. Returns True if restart needed."""
        if not self._is_started():
            return False
        self._update_keystore_and_reload(keystore)
        return any(
            [
                self.distro.config.delete(self.CONFIG_YML, c, v)[c] == v
                for c, v in opensearch_yml.items()
            ]
        )

    @property
    def needs_upgrade(self) -> bool:
        """Returns if the plugin needs an upgrade or not.

        Needs upgrade must be set if an upgrade on the charm happens and plugins must
        be updated.

        Consider overriding this method only if the plugin needs an special care at upgrade.
        """
        current_version = self.version
        # Now check if the format of this plugin and OpenSearch's match
        num_points = len(self.distro.version.split("."))
        return self.distro.version != current_version[:num_points]

    @abstractmethod
    def upgrade(self, uri: str) -> None:
        """Runs the upgrade process in this plugin."""
        pass

    @abstractmethod
    def is_enabled(self) -> bool:
        """Returns True if the plugin is enabled."""
        pass

    @abstractmethod
    def disable(self) -> bool:
        """Disables the plugin.

        Runs the configure() method with the configuration to disable the plugin.
        """
        pass

    @abstractmethod
    def enable(self) -> bool:
        """Enables the plugin.

        Runs the configure() method with the configuration to enable the plugin.
        """
        pass

    def configure(
        self,
        opensearch_yml: Dict[str, str],
        keystore: Dict[str, str] = {},
    ) -> bool:
        """Sets the plugin configuration. Returns True if restart needed."""
        if not self._is_started():
            return False
        self._update_keystore_and_reload(keystore)
        return any(
            [
                self.distro.config.put(self.CONFIG_YML, c, v)[c] == v
                for c, v in opensearch_yml.items()
            ]
        )

    def is_installed(self) -> bool:
        """Returns True if the plugin name is present in the list of installed plugins."""
        if not self._is_started():
            return False
        return self.name in self.distro.list_plugins()

    def install(self, uri: str, batch=True) -> bool:
        """Installs the plugin specified in the URI.

        The URI can have one of the following formats:
        * A zip file
        * An URL that downloads a zip file
        * A maven coded dependency
        """
        if self.is_installed():
            # It is already available as a plugin, return True
            return True
        if self._depends_on:
            plugins = self.distro.list_plugins()
            missing = []
            for dependency in self.depends_on:
                if dependency not in plugins:
                    missing.append(dependency)
                if dependency:
                    raise OpenSearchPluginError("Missing dependencies")
        self.distro.add_plugin_without_restart(uri, batch=batch)

    @property
    @abstractmethod
    def depends_on(self) -> List[str]:
        """Returns a list of plugins it depends on."""
        pass

    def get_status(self) -> Union[int, StatusBase]:
        """Returns the status of the plugin.

        Status:
            0: blocked, not installed
            1: blocked, not enabled
            2: active
            3: blocked, waiting for an upgrade action
        """
        code = 0
        if not self.is_installed():
            return code, BlockedStatus(f"Plugin {self.name} waiting to be installed")
        elif self.is_enabled():
            code = 1
            return code, BlockedStatus(f"Plugin {self.name} waiting to be enabled")
        elif not self.needs_upgrade:
            code = 2
            return code, ActiveStatus(f"Plugin {self.name} active")
        code = 3
        return code, BlockedStatus(f"Plugin {self.name} waiting for upgrade to be executed")


class OpenSearchPluginManager:
    """Manages the currently enabled plugins."""

    def __init__(self, charm: Object):
        self._charm = charm

    @property
    def plugins(self) -> Dict[str, OpenSearchPlugin]:
        """Returns dict of installed plugins."""
        return {
            key: plugin_data["class"](key, self._charm)
            for key, plugin_data in OpenSearchPluginsAvailable.items()
        }

    def plugin_map_config_name_to_class(self) -> Dict[str, OpenSearchPlugin]:
        """Returns dict of plugins installed either via config or relation.

        The dict has the format:
            {
                "{relation,config}-name": <class>,
            }
        Relation names will take precedence over config.
        """
        return {
            plugin_data["relation-name"]
            if plugin_data.get("relation-name", None)
            else plugin_data["config-name"]: plugin_data["class"](key, self._charm)
            for key, plugin_data in OpenSearchPluginsAvailable.items()
        }

    def get_status(self) -> StatusBase:
        """Returns if one of the plugins are not active, otherwise, returns active status."""
        for stat in self.plugins:
            if not isinstance(stat, ActiveStatus):
                return stat
        return ActiveStatus("")

    def plugins_need_upgrade(self) -> List[OpenSearchPlugin]:
        """Returns a list of plugins that need upgrade."""
        return [name for name, obj in self.plugins.items() if obj.needs_upgrade]
