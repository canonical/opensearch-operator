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


For a new plugin, add the plugin to the list of "OpenSearchPluginsAvailable" in
opensearch_distro.py and override the abstract OpenSearchPlugin.

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
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from charms.opensearch.v0.opensearch_exceptions import OpenSearchPluginError
from ops.framework import Object

# The unique Charmhub library identifier, never change it
LIBID = "3b05456c6e304680b4af8e20dae246a2"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OpenSearchPlugin(ABC):
    """Abstract class describing an OpenSearch plugin."""

    PLUGIN_PROPERTIES = "plugin-descriptor.properties"
    SECURITY_POLICY = "plugin-security.policy"
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

    def _update_keystore_and_reload(self, keystore: Dict[str, str], force: bool = True) -> None:
        if not keystore:
            return
        for key, value in keystore.items():
            self.distro.add_to_keystore(key, value, force=force)
        # Now, reload the security settings and return if opensearch needs restart
        try:
            post = self._request("POST", "_nodes/reload_secure_settings")
        except Exception as e:
            raise OpenSearchPluginError(
                f"configure of {self.name}:lugin error at secure reload: {e}"
            )
        if post["status"] < 200 or post["status"] >= 300:
            raise OpenSearchPluginError(
                f"configure of {self.name}: error when posting secure reload"
            )

    @property
    def name(self) -> str:
        """Returns the name of the plugin."""
        return self._name

    @property
    def version(self) -> str:
        """Returns the current version of the plugin."""
        return self._plugin_properties.load(self.PLUGIN_PROPERTIES)["version"]

    def uninstall(
        self,
        opensearch_yml: Dict[str, str],
        keystore: Dict[str, str],
    ) -> bool:
        """Erases relevant data for this plugin. Returns True if restart needed."""
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
        """
        raise NotImplementedError

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
        self._update_keystore_and_reload(keystore)
        return any(
            [
                self.distro.config.put(self.CONFIG_YML, c, v)[c] == v
                for c, v in opensearch_yml.items()
            ]
        )

    def is_installed(self) -> bool:
        """Returns True if the plugin name is present in the list of installed plugins."""
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
