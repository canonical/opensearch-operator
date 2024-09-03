# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Plugin Model.

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
ENABLING_NEEDED (the user requested to be enabled, but not configured yet) >
ENABLED (configuration has been applied) >
DISABLING_NEEDED (is_enabled returns True but user is not requesting anymore) >
DISABLED (disabled by removing options) > WAITING_FOR_UPGRADE >
ENABLED (back to enabled state once upgrade has been applied)

WHERE PLUGINS ARE USED:
Plugins are managed in the OpenSearchPluginManager class, which is called by the charm;
and also in the code that manages the relations, e.g. OpenSearchBackups. The latter may
access one or more plugins directly to retrieve information for their own relations.

ERROR HANDLING:
Plugins can raise errors that subclass OpenSearchPluginError. In the case of the charm,
these errors are handled by the plugin manager and the charm at config-changed. In this
case, plugin manager receives the error and prepares a status message to be returned to the
charm. The charm will then set the status message at the end of config-changed.


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

        # If using the self._extra_config, or any other dict to build the class below
        # let the KeyError happen and the plugin manager will capture it.
        try:
            return OpenSearchPluginConfig(
                config_entries={...}, # Key-value pairs to be added to opensearch.yaml
                secret_entries={...}  # Key-value pairs to be added to keystore
            )
        except MyPluginError as e:
            # If we want to set the status message with str(e), then raise it with:
            raise e

    def disable(self) -> Tuple[OpenSearchPluginConfig, OpenSearchPluginConfig]:
        # Use the self._extra_config to retrieve any extra configuration.

        # If using the self._extra_config, or any other dict to build the class below
        # let the KeyError happen and the plugin manager will capture it.
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

    config_entries: Dict[str, str] = {
        ... key, values to add to the config as plugin gets enabled ...
    }
    secret_entries: Dict[str, str] = {
        ... key, values to add to to keystore as plugin gets enabled ...
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
        super().__init__(charm, relation_name, peer_relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._peer_relation_name = peer_relation_name

        self.my_client = MyPluginRelationRequirer(self.charm, relation_name)
        self.framework.observe(
            self.charm.on[relation_name].relation_created, self._event_handler
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_changed, self._event_handler
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_departed, self._event_handler
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_broken, self._event_handler
        )

    @property
    def relation(self):
        return self._charm.model.get_relation(self._relation_name)

    @property
    def peer_relation(self):
        return self._charm.model.get_relation(self._peer_relation_name)

    def _event_handler(self, event):

        # Due to LP#2024583, we need to be sure there are units in the relation before
        # calling plugin_manager.run() and processing the units.
        # Therefore, check these scenarios
        relation = self._charm.model.get_relation(self._relation_name)
        if (isinstance(event, RelationJoinedEvent)
            and (not relation or not relation.units)):
            # We must wait to execute these relations until there are units adding data
            # First, make sure the status is stored
            self.peer_relation.data[self._charm.unit]["MyPlugin_waiting_for_rel_units"] = True
            # Now, defer the event and wait
            event.defer()
            return
        elif (isinstance(event, RelationBrokenEvent)
              and (relation or relation.units)):
            # Same case here
            self.peer_relation.data[self._charm.unit]["MyPlugin_waiting_for_rel_units"] = True
            # Now, defer the event and wait
            event.defer()
            return

        # Due to LP#2024583, if we are waiting for a previous event, then defer
        if self.peer_relation.data[self._charm.unit].get("MyPlugin_waiting_for_rel_units"):
            event.defer()
            return
        self.peer_relation.data[self._charm.unit]["MyPlugin_waiting_for_rel_units"] = False

        ...

        # Execute any other tasks, e.g. running API calls to OpenSearch
        # Optionally, use other methods to execute specifics, e.g. _event_departed
        ...

        # Call the plugin manager to process the new relation data
        if self._charm.plugin_manager.run():
            # Call the restart logic

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

"""  # noqa: D405, D410, D411, D214, D412, D416

import json
import logging
from abc import abstractmethod, abstractproperty
from typing import Any, Dict, List, Optional

from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.models import S3RelData, S3RelDataCredentials
from charms.opensearch.v0.opensearch_exceptions import OpenSearchError
from jproperties import Properties
from pydantic import BaseModel, validator
from pydantic.error_wrappers import ValidationError

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


class OpenSearchPluginMissingConfigError(OpenSearchPluginError):
    """Exception thrown when config() or disable() fails to find a config key.

    The plugin itself should raise a KeyError, to avoid burden in the plugin development.
    """


class OpenSearchPluginEventScope(BaseStrEnum):
    """Defines the scope of the plugin manager."""

    DEFAULT = "default"
    RELATION_BROKEN_EVENT = "relation-broken-event"


class PluginState(BaseStrEnum):
    """Enum for the states possible in plugins' lifecycle."""

    MISSING = "missing"
    INSTALLED = "installed"
    ENABLING_NEEDED = "enabling-needed"
    ENABLED = "enabled"
    DISABLING_NEEDED = "disabling-needed"
    DISABLED = "disabled"
    WAITING_FOR_UPGRADE = "waiting-for-upgrade"


class OpenSearchPluginConfig(BaseModel):
    """Represent the configuration of a plugin to be applied when configuring or disabling it.

    The config may receive any type of data, but will convert everything to strings and
    pay attention to special types, such as booleans, which need to be "true" or "false".
    """

    config_entries: Optional[Dict[str, Any]] = {}
    secret_entries: Optional[Dict[str, Any]] = {}

    @validator("config_entries", "secret_entries", allow_reuse=True, pre=True)
    def convert_values(cls, conf) -> Dict[str, str]:  # noqa N805
        """Converts the object to a dictionary.

        Respects the conversion for boolean to {"true", "false"}.
        """
        result = {}
        for key, val in conf.items():
            if not val:
                result[key] = None
                continue
            if isinstance(val, bool):
                result[key] = str(val).lower()
            else:
                result[key] = str(val)
        return result

    def __str__(self) -> str:
        """Returns the string representation of the plugin config_entries.

        This method is intended to convert the object to a string for HTTP. The main goal
        is to convert to a JSON string and replace any None entries with a null (without quotes).
        """
        return json.dumps(self.config_entries)


class OpenSearchPluginMeta(type):
    """Metaclass to ensure only one instance of each plugin is created."""

    _plugins = {}

    def __call__(cls, *args, **kwargs):
        """Sets singleton class in this hook.

        This singleton guarantees we won't have multiple instances dealing with objects such as
        relations at once. This is forbidden by the operator framework.

        Besides that, it allows us to have a single instance of each plugin, loaded with particular
        information at init such as which relation to look for or which config to use. That
        creation happens either at plugin manager or at the relation manager's creation.
        """
        if cls not in cls._plugins:
            obj = super().__call__(*args, **kwargs)
            cls._plugins[cls] = obj
        return cls._plugins[cls]


class OpenSearchPlugin(metaclass=OpenSearchPluginMeta):
    """Abstract class describing an OpenSearch plugin."""

    PLUGIN_PROPERTIES = "plugin-descriptor.properties"
    REMOVE_ON_DISABLE = False

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
        return []

    @abstractmethod
    def config(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin addition.

        May throw KeyError if accessing some source, such as self._extra_config, but the
        dictionary does not contain all the configs. In this case, let the error happen.
        """
        pass

    @abstractmethod
    def disable(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin removal.

        May throw KeyError if accessing some source, such as self._extra_config, but the
        dictionary does not contain all the configs. In this case, let the error happen.
        """
        pass

    @abstractproperty
    def name(self) -> str:
        """Returns the name of the plugin."""
        pass


class OpenSearchPluginRelationsHandler(OpenSearchPlugin):
    """Implements a handler for the relation databag.

    Plugins may have one or more relations tied to them. This abstract class
    enables different modules to implement a class that can specify which
    relations should plugin manager listen to.

    There is a difference between OpenSearchPluginRelationsHandler.data and
    OpenSearchPluginRelationsHandler.config/disable: the former is possible to be overridden and
    it represents the entire data from the relation databag, while the latter represents what
    the plugin_manager should have access so it can configure /_cluster/settings APIs.
    """

    MODEL = None

    def __init__(self, *args, **kwargs):
        """Creates the OpenSearchPluginRelationsHandler object."""
        super().__init__(*args, **kwargs)

    def is_relation_set(self) -> bool:
        """Returns True if the relation is set, False otherwise.

        It can mean the relation exists or not, simply put; or it can also mean a subset of data
        exists within a bigger relation. One good example, peer-cluster is a single relation that
        contains a lot of different data. In this case, we'd be interested in a subset of
        its entire databag.

        It can also mean there is a secret with content available or not.
        """
        return NotImplementedError()

    @property
    def data(self) -> BaseModel:
        """Returns the data from the relation databag.

        Exceptions:
            ValueError: if the data is not valid
        """
        raise NotImplementedError()

    @data.setter
    def data(self, value: Dict[str, Any]):
        """Sets the data from the relation databag.

        Exceptions:
            ValueError: if the data is not valid
        """
        raise NotImplementedError()

    def update_secrets(self, secret_map: Dict[str, Any]) -> bool:
        """Update the secrets using secret_map.

        The plugin classes should not be aware of charm details, such as OpenSearchSecrets.
        Therefore, update_secrets is the API to pass the new values to the plugin.
        """
        raise NotImplementedError()


class OpenSearchKnn(OpenSearchPlugin):
    """Implements the opensearch-knn plugin."""

    def config(self) -> OpenSearchPluginConfig:
        """Returns a plugin config object to be applied for enabling the current plugin."""
        return OpenSearchPluginConfig(
            config_entries={"knn.plugin.enabled": True},
        )

    def disable(self) -> OpenSearchPluginConfig:
        """Returns a plugin config object to be applied for disabling the current plugin."""
        return OpenSearchPluginConfig(
            config_entries={"knn.plugin.enabled": False},
        )

    @property
    def name(self) -> str:
        """Returns the name of the plugin."""
        return "opensearch-knn"


class OpenSearchBackupPlugin(OpenSearchPluginRelationsHandler):
    """Manage backup configurations.

    This class must load the opensearch plugin: repository-s3 and configure it.

    The plugin is responsible for managing the backup configuration, which includes relation
    databag or only the secrets' content, as backup changes behavior depending on the juju app
    role within the cluster.
    """

    MODEL = S3RelData

    def __init__(self, plugin_path, relation_data, is_main_orchestrator, repo_name=None):
        """Creates the OpenSearchBackupPlugin object."""
        super().__init__(plugin_path, relation_data)
        self.is_main_orchestrator = is_main_orchestrator
        self.repo_name = repo_name or "default"

    @property
    def data(self) -> BaseModel:
        """Returns the data from the relation databag."""
        try:
            return self.MODEL.from_relation(self._extra_config)
        except ValidationError:
            return self.MODEL()

    @data.setter
    def data(self, value: Dict[str, Any]):
        """Sets the data from the relation databag."""
        self._extra_config = value

    def update_secrets(self, secret_map: Dict[str, Any]) -> bool:
        """Update the secrets using secret_map."""
        self.data.credentials = S3RelDataCredentials(**secret_map)
        return self.data.credentials.access_key and self.data.credentials.secret_key

    def is_relation_set(self) -> bool:
        """Returns True if the relation is set, False otherwise."""
        try:
            self.config()
        except OpenSearchPluginMissingConfigError:
            return False
        return True

    @property
    def name(self) -> str:
        """Returns the name of the plugin."""
        return "repository-s3"

    def config(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin configuration."""
        conf = self.data.credentials.dict()
        if self.is_main_orchestrator:
            conf = self.data.dict()
        if any([val is None for val in conf.values()]):
            raise OpenSearchPluginMissingConfigError(
                "Plugin {} missing: {}".format(
                    self.name,
                    [key for key, val in conf.items() if val is None],
                )
            )

        if not self.is_main_orchestrator:
            return OpenSearchPluginConfig(
                secret_entries={
                    f"s3.client.{self.repo_name}.access_key": self.data.credentials.access_key,
                    f"s3.client.{self.repo_name}.secret_key": self.data.credentials.secret_key,
                },
            )
        # This is the main orchestrator
        return OpenSearchPluginConfig(
            config_entries={
                f"s3.client.{self.repo_name}.endpoint": self.data.endpoint,
                f"s3.client.{self.repo_name}.region": self.data.region,
                f"s3.client.{self.repo_name}.protocol": self.data.protocol,
            },
            secret_entries={
                f"s3.client.{self.repo_name}.access_key": self.data.credentials.access_key,
                f"s3.client.{self.repo_name}.secret_key": self.data.credentials.secret_key,
            },
        )

    def disable(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin removal."""
        return OpenSearchPluginConfig(
            config_entries={
                f"s3.client.{self.repo_name}.endpoint": None,
                f"s3.client.{self.repo_name}.region": None,
                f"s3.client.{self.repo_name}.protocol": None,
            },
            secret_entries={
                f"s3.client.{self.repo_name}.access_key": None,
                f"s3.client.{self.repo_name}.secret_key": None,
            },
        )
