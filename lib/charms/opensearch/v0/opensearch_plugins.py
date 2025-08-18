# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
from abc import abstractmethod
from os import access
from typing import Any, Dict, List, Optional

from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.models import (
    AzureRelDataCredentials,  # , S3RelDataCredentials
)
from charms.opensearch.v0.opensearch_exceptions import OpenSearchError
from jproperties import Properties
from pydantic import BaseModel, validator
from ops.framework import Object

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
            # First, we deal with the case the value is an actual bool
            # If yes, then we need to convert to a lower case string
            if isinstance(val, bool):
                result[key] = str(val).lower()
            elif not val:
                # Exclude this key from the final settings.
                # Now, we can process the case where val may be empty.
                # This way, a val == False will return 'false' instead of None.
                result[key] = None
            else:
                result[key] = str(val)
        return result

    def __str__(self) -> str:
        """Returns the string representation of the plugin config_entries.

        This method is intended to convert the object to a string for HTTP. The main goal
        is to convert to a JSON string and replace any None entries with a null (without quotes).
        """
        return json.dumps(self.config_entries)


class OpenSearchPlugin:
    """Abstract class describing an OpenSearch plugin."""

    PLUGIN_PROPERTIES = "plugin-descriptor.properties"
    REMOVE_ON_DISABLE = False

    name = None

    def __init_subclass__(cls, **kwargs):
        """Creates the OpenSearchPlugin subclass"""
        super().__init_subclass__(**kwargs)
        if not cls.name or not isinstance(cls.name, str):
            raise TypeError(f"{cls.__name__} attribute 'name' must be a non-empty string")

    def __init__(self, charm, manager):
        """Creates the OpenSearchPlugin object."""
        self._plugins_path = (
            f"{charm.opensearch.paths.plugins}/{self.name}/{self.PLUGIN_PROPERTIES}"
        )
        self._extra_config = charm.config
        self._settings_manager = manager

    @property
    def plugin_name(self) -> str:
        """Returns the name of the plugin."""
        return type(self).name

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
    def requested_to_enable(self) -> bool:
        """Returns True if self._extra_config states as enabled."""
        pass

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


class OpenSearchPluginDataProvider:
    """Implements the data provider for any charm-related data access.

    Plugins may have one or more relations tied to them. This abstract class
    enables different modules to implement a class that can specify which
    relations should plugin manager listen to.
    """

    def __init__(self, charm):
        """Creates the OpenSearchPluginDataProvider object."""
        self._charm = charm

    @abstractmethod
    def get_relation(self) -> Any:
        """Returns the relation object if it's not set yet."""
        pass

    @abstractmethod
    def get_data(self) -> Dict[str, Any]:
        """Returns the data from the relation databag.

        Exceptions:
            ValueError: if the data is not valid
        """
        raise NotImplementedError


class OpenSearchKnn(OpenSearchPlugin):
    """Implements the opensearch-knn plugin."""

    name = "opensearch-knn"

    def requested_to_enable(self) -> bool:
        """Returns True if the plugin is enabled."""
        return self._extra_config["plugin_opensearch_knn"]

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


class OpenSearchS3Plugin(OpenSearchPlugin, Object):
    """Manage backup configurations.

    This class must load the opensearch plugin: repository-s3 and configure it.

    The plugin is responsible for managing the backup configuration, which includes relation
    databag or only the secrets' content, as backup changes behavior depending on the juju app
    role within the cluster.
    """

    name = "repository-s3"

    def __init__(self, charm, manager):
        # super().__init__(charm, manager)
        OpenSearchPlugin.__init__(self, charm, manager)
        Object.__init__(self, charm, f"plugin:{self.name}")
        self.relation_name = "s3-credentials"
        self._s3 = S3Requirer(charm, self.relation_name)
        self.data = None
        self.framework.observe(charm.on[self.relation_name].relation_changed, self._on_relation_changed)

    def _on_relation_changed(self, event):
        self._update_data(self._s3.get_s3_connection_info())

    def _update_data(self, connection_info):
        data = self._s3.get_s3_connection_info()
        attributes_raw = data.get("attributes", "")
        attributes = dict(item.split("=", 1) for item in attributes_raw.split(",") if "=" in item)
        client_name = attributes.get("client", None) or 'default'
        access_key = data.get("access-key")
        secret_key = data.get("secret-key")
        if access_key and secret_key:
            keystore = { f"s3.client.{client_name}.access_key" : access_key, f"s3.client.{client_name}.secret_key" : secret_key }
            self.data = { "keystore": keystore }
            self._settings_manager.persist(self.data)

        # self._relations = ["s3-credentials"]

    # def __init__(self, charm, relation_data: S3RelDataCredentials | None = None):
    #     """Creates the OpenSearchBackupPlugin object."""
    #     super().__init__(charm)
    #     self.repo_name = "default"
    #     self.charm = charm
    #     if relation_data and not (relation_data.access_key and relation_data.secret_key):
    #         self.data = None
    #     else:
    #         self.data = relation_data
    #
    # def requested_to_enable(self) -> bool:
    #     """Returns True if the plugin is enabled."""
    #     return self.data is not None
    #
    # @property
    # def name(self) -> str:
    #     """Returns the name of the plugin."""
    #     return "repository-s3"
    #
    # def config(self) -> OpenSearchPluginConfig:
    #     """Returns OpenSearchPluginConfig composed of configs used at plugin configuration."""
    #     if not self.data:
    #         # Nothing to do, the backup is not enabled anyways
    #         return self.disable()
    #
    #     return OpenSearchPluginConfig(
    #         config_entries={},
    #         secret_entries={
    #             f"s3.client.{self.repo_name}.access_key": self.data.access_key,
    #             f"s3.client.{self.repo_name}.secret_key": self.data.secret_key,
    #         },
    #     )
    #
    # def disable(self) -> OpenSearchPluginConfig:
    #     """Returns OpenSearchPluginConfig composed of configs used at plugin removal."""
    #     return OpenSearchPluginConfig(
    #         config_entries={},
    #         secret_entries={
    #             f"s3.client.{self.repo_name}.access_key": None,
    #             f"s3.client.{self.repo_name}.secret_key": None,
    #         },
    #     )


class OpenSearchAzurePlugin(OpenSearchPlugin):
    """Manage backup configurations.

    This class must load the opensearch plugin: repository-azure and configure it.

    The plugin is responsible for managing the backup configuration, which includes relation
    databag or only the secrets' content, as backup changes behavior depending on the juju app
    role within the cluster.
    """

    name = "repository-azure"

    def __init__(self, charm, relation_data):
        """Creates the OpenSearchAzurePlugin object."""
        super().__init__(charm)
        self.repo_name = "default"
        self.charm = charm
        self.data = None
        # if relation_data and not (relation_data.storage_account and relation_data.secret_key):
        #     self.data = None
        # else:
        #     self.data = relation_data

    def requested_to_enable(self) -> bool:
        """Returns True if the plugin is enabled."""
        return self.data is not None

    def config(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin configuration."""
        if not self.data:
            # Nothing to do, the backup is not enabled anyways
            return self.disable()

        return OpenSearchPluginConfig(
            config_entries={},
            secret_entries={
                f"azure.client.{self.repo_name}.account": self.data.storage_account,
                f"azure.client.{self.repo_name}.key": self.data.secret_key,
            },
        )

    def disable(self) -> OpenSearchPluginConfig:
        """Returns OpenSearchPluginConfig composed of configs used at plugin removal."""
        return OpenSearchPluginConfig(
            config_entries={},
            secret_entries={
                f"azure.client.{self.repo_name}.account": None,
                f"azure.client.{self.repo_name}.key": None,
            },
        )
