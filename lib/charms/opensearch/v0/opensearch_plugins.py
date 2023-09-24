# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Plugin model.

In OpenSearch, plugins are also called interchangeably as extensions and modules.

A plugin configuration footprint is composed of:
* Jar files installed in one of the
  ${OPENSEARCH_HOME}/plugins
  ${OPENSEARCH_HOME}/modules
* Configuration passed to the main opensearch.yml
* Secrets stored in the keystore
* The plugin description: plugin.properties
* The security policy in: security.policy
* API calls to opensearch cluster to configure or remove configuration
* Other plugins which it depends upon

One last piece of the configuration is any index data uploaded to the cluster using
OpenSearch APIs. That last bit of data must be done by inherinting the OpenSearchPlugin
class and implementing the necessary extra logic.


This file implements abstract methods and data that are common to every plugin during
its lifecycle, including methods to manage configuration files, main processes (install,
upgrade, uninstall, etc).

The plugin lifecycle runs through the following steps:

MISSING (not installed yet) > INSTALLED (plugin installed, but not configured yet) >
ENABLED (configuration has been applied) > WAITING_FOR_UPGRADE (if an upgrade is needed)
> ENABLED (back to enabled state once upgrade has been applied)

========================================================================================

                             STEPS TO ADD A NEW PLUGIN

========================================================================================


Every plugin is defined either by a configuration parameter or a relation passed to the
OpenSearch charm. When enabled, a class named "OpenSearchPluginManager" will allocate
the OpenSearchPlugin and pass the config/relation data to be processed by the new plugin
class.


The development of a new plugin should be broken into 3x classes:
1) The OpenSearchPlugin, that represents everything related to the configuration
2) Optionally, the OpenSearchPluginConfig, a class that contains the configuration
   options as dictionaries
3) Optionally, a charm-level class, that should be managed directly by the charm and is
   is used to handle the APIs and relation events


One example:


from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchPlugin,
    OpenSearchPluginConfig
)


class MyPlugin(OpenSearchPlugin):

    def __init__(self, plugins_path: str, extra_config: Dict[str, Any] = None):
        super().__init__(plugins_path, extra_config)

        # self._extra_config is defined in the super constructor above
        # Plugin Manager will always pass either the config value or the

        ...

    @property
    def dependencies(self) -> List[str]:
        return [...] # List of names of plugins that MyPlugin needs before installation

    def config(self) -> OpenSearchPluginConfig:
        # Use the self._extra_config to retrieve any extra configuration.

        return OpenSearchPluginConfig(
            config_entries_on_add={...}, # Key-value pairs to be added to opensearch.yaml
            secret_entries_on_add={...}  # Key-value pairs to be added to keystore
        )

    def disable(self) -> Tuple[OpenSearchPluginConfig, OpenSearchPluginConfig]:
        # Use the self._extra_config to retrieve any extra configuration.

        return (
            OpenSearchPluginConfig(...), # Configuration to be removed from yaml/keystore
                                         # Configuration to be added, e.g. in the case we need
                                         # to restore original values or set the plugin config
                                         # as false

    @property
    def name(self) -> str:
        return "my-plugin"


-------------------

Optionally:
class MyPluginConfig(OpenSearchPluginConfig):

    config_entries_to_add: Dict[str, str] = {
        ... key, values to add to the config as plugin gets enabled ...
    }
    config_entries_to_del: Dict[str, str] = {
        ... key, values to remove to the config as plugin gets disabled ...
    }
    secret_entries_to_add: Dict[str, str] = {
        ... key, values to add to to keystore as plugin gets enabled ...
    }
    secret_entries_to_del: Dict[str, str] = {
        ... key, values to remove from keystore as plugin gets disabled ...
    }

-------------------

For a new plugin, add the plugin to the list of "ConfigExposedPlugins" available
in opensearch_plugin_manager.py and override the abstract OpenSearchPlugin.

Add a new configuration in the config.yaml with "plugin_" as prefix to its name.
Add the corresponding config to the ConfigExposedPlugins. For example:
    ConfigExposedPlugins = {
        ...
        "opensearch-knn": {
            "class": OpenSearchPlugin,
            "config": "plugin_opensearch_knn",
            "relation": None
        },
    }

If a given plugin depends on a relation, e.g. repository-s3, then add relation name
instead:
    ConfigExposedPlugins = {
        ...
        "repository-s3": {
            "class": MyOpenSearchBackupPlugin,
            "config": None,
            "relation": "backup-relation"
        },
    }


-------------------

In case the plugin depends on API calls to finish configuration or a relation to be
configured, create an extra class at the charm level to manage plugin events:


class MyPluginRelationManager(Object):

    PLUGIN_NAME = "MyPlugin"

    def __init__(self, charm: OpenSearchBaseCharm, relation_name: str):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name

        self.my_client = MyPluginRelationRequirer(self.charm, relation_name)
        self.framework.observe(
            self.charm.on[relation_name].relation_departed, self.on_change
        )

    def on_change(self, event):
        ...
        # Call the plugin manager to process the new relation data
        self._charm.plugin_manager.run()

        # Or search for the specific plugin
        # That may be relevant if we need to recover configuration data, for example
        # to submit in an API call
        for plugin in self._charm.plugin_manager.plugins():
            if plugin.name == PLUGIN_NAME:
                self._run_the_api_call_here(plugin.config())

...


class OpenSearchBaseCharm(CharmBase):

    def __init__(self, *args, distro: Type[OpenSearchDistribution] = None):
        ...

        self.my_plugin_relation = MyPluginRelationManager(self)

    ...

    def _on_update_status(self, event):
        ...

        # Check my plugin status
        if self.model.get_relation("my-plugin-relation") is not None:
            self.unit.status = self.my_plugin.status()

        for relation in self.model.relations.get(ClientRelationName, []):
            self.opensearch_provider.update_endpoints(relation)

        self.user_manager.remove_users_and_roles()
        # If relation not broken - leave
        if self.model.get_relation("certificates") is not None:
            return
        # handle when/if certificates are expired
        self._check_certs_expiration(event)
"""

import logging
from abc import abstractmethod, abstractproperty
from typing import Any, Dict, List, Optional

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


class OpenSearchPluginInstallError(OpenSearchPluginError):
    """Exception thrown when opensearch plugin installation fails."""


class OpenSearchPluginRemoveError(OpenSearchPluginError):
    """Exception thrown when opensearch plugin removal fails."""


class PluginState(BaseStrEnum):
    """Enum for the states possible in plugins' lifecycle."""

    MISSING = "missing"
    INSTALLED = "installed"
    ENABLED = "enabled"
    WAITING_FOR_UPGRADE = "waiting-for-upgrade"


class OpenSearchPluginConfig:
    """Represent the configuration of a plugin to be applied when configuring or disabling it."""

    def __init__(
        self,
        config_entries_to_add: Optional[Dict[str, str]] = None,
        config_entries_to_del: Optional[Dict[str, str]] = None,
        secret_entries_to_add: Optional[Dict[str, str]] = None,
        secret_entries_to_del: Optional[Dict[str, str]] = None,
    ):
        self.config_entries_to_add = config_entries_to_add or {}
        self.config_entries_to_del = config_entries_to_del or {}
        self.secret_entries_to_add = secret_entries_to_add or {}
        self.secret_entries_to_del = secret_entries_to_del or {}


class OpenSearchPlugin:
    """Abstract class describing an OpenSearch plugin."""

    PLUGIN_PROPERTIES = "plugin-descriptor.properties"

    def __init__(self, plugins_path: str, extra_config: Dict[str, Any] = None):
        """Creates the OpenSearchPlugin object.

        Arguments:
          plugins_path: str, path to the plugins folder
          extra_config: dict, contains config entries coming from optional relation data
        """
        self._plugins_path = f"{plugins_path}/{self.name}/{self.PLUGIN_PROPERTIES}"
        self._extra_config = extra_config

    @property
    def version(self) -> str:
        """Returns the current version of the plugin.

        Returns: str, string with the version code for this plugin
        Raises:
            FileNotFoundError: if plugin file is not present
            PermissionError: if plugin file is present, but not set with correct permissions
        """
        properties = Properties()
        with open(self._plugins_path) as f:
            properties.load(f.read())
        return properties._properties["version"]

    @property
    def dependencies(self) -> Optional[List[str]]:
        """Returns a list of plugin name dependencies."""
        return None

    @abstractmethod
    def config(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin addition.

        Format:
        OpenSearchPluginConfig(
            config_entries_to_add = {...},
            config_entries_to_del = {...},
            secret_entries_to_add = {...},
            secret_entries_to_del = {...},
        )
        """
        pass

    @abstractmethod
    def disable(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin removal.

        Format:
        OpenSearchPluginConfig(
            config_entries_to_add = {...},
            config_entries_to_del = {...},
            secret_entries_to_add = {...},
            secret_entries_to_del = {...},
        )
        """
        pass

    @abstractproperty
    def name(self) -> str:
        """Returns the name of the plugin."""
        pass


class OpenSearchKnn(OpenSearchPlugin):
    """Implements the opensearch-knn plugin."""

    def config(self) -> OpenSearchPluginConfig:
        """Returns a plugin config object to be applied for enabling the current plugin."""
        return OpenSearchPluginConfig(
            config_entries_to_add={"knn.plugin.enabled": True},
        )

    def disable(self) -> OpenSearchPluginConfig:
        """Returns a plugin config object to be applied for disabling the current plugin."""
        return OpenSearchPluginConfig(
            config_entries_to_add={"knn.plugin.enabled": False},
        )

    @property
    def name(self) -> str:
        """Returns the name of the plugin."""
        return "opensearch-knn"
