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
import re
from abc import abstractmethod
from os.path import exists
from typing import Dict, List, Optional

from charms.opensearch.v0.helper_conf_setter import ConfigSetter, OutputType
from charms.opensearch.v0.opensearch_exceptions import OpenSearchPluginError
from ops.framework import Object
from overrides import override

# The unique Charmhub library identifier, never change it
LIBID = "3b05456c6e304680b4af8e20dae246a2"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OpenSearchPlugin(Object):
    """Abstract class describing an OpenSearch plugin."""

    PLUGIN_PROPERTIES = "plugin-descriptor.properties"
    SECURITY_POLICY = "plugin-security.policy"
    CONFIG_YML = "opensearch.yml"

    def __init__(self, name: str, charm: Object, relname: Optional[str]):
        """Creates the OpenSearchPlugin object.

        The *args enable children classes to pass relations.
        """
        super().__init__(charm, relname)
        self.charm = charm
        self.distro = self.charm.opensearch
        self.CONFIG_YML = self.charm.opensearch_config.CONFIG_YML
        self._name = name
        self._plugin_properties = PluginPropertiesSetter(
            base_path=f"{self.distro.paths.plugins}/plugins/{self.name}/"
        )
        self._security_policy = SecurityPolicySetter(
            base_path=f"{self.distro.paths.plugins}/plugins/{self.name}/"
        )

    def _update_keystore_and_reload(self, keystore: Dict[str, str]) -> None:
        if not keystore:
            return
        for c, v in keystore.items():
            self.distro.add_to_keystore(c, v, force=True)
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
        ret = False
        for c, v in opensearch_yml.items():
            ret = ret or self.distro.config.delete(self.CONFIG_YML, c, v)[c] == v

        self._update_keystore_and_reload(keystore)
        return ret

    @property
    def needs_upgrade(self) -> bool:
        """Returns if the plugin needs an upgrade or not.

        Needs upgrade must be set if an upgrade on the charm happens and plugins must
        be updated.
        """
        pass

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
        properties: Dict[str, str] = {},
        security: Dict[str, str] = {},
        keystore: Dict[str, str] = {},
    ) -> bool:
        """Sets the plugin configuration. Returns True if restart needed."""
        ret = False
        for c, v in opensearch_yml.items():
            ret = ret or self.distro.config.put(self.CONFIG_YML, c, v)[c] == v
        for c, v in properties.items():
            ret = ret or self._plugin_properties.put(self.PLUGIN_PROPERTIES, c, v)[c] == v
        for c, v in security.items():
            ret = ret or self._security_policy.put(self.SECURITY_POLICY, c, v)[c] == v
        self._update_keystore_and_reload(keystore)
        return ret

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
            for d in self.depends_on:
                if d not in plugins:
                    missing.append(d)
                if d:
                    raise OpenSearchPluginError("Missing dependencies")
        self.distro.add_plugin_without_restart(uri, batch=batch)

    @property
    def depends_on(self) -> List[str]:
        """Returns a list of plugins it depends on."""
        return []


class SimplePropertiesSetter(ConfigSetter):
    """Represents a simple java properties file.

    Process a simple properties/policy file and renders one of the two structures:
        {
            el1: {
                el2: []
            }
        }
        OR
        {
            el1: []
        }
    Only depth <= 2 is allowed.
    """

    def __init__(self, base_path):
        super().__init__(base_path)
        self.base_path = base_path

    @abstractmethod
    def load(self, config_file: str) -> Dict[str, any]:
        """Loads the config_file and returns its settings."""
        pass

    @abstractmethod
    def dump(self, data: Dict[str, any], output_type: OutputType, target_file: str):
        """Saves the data to the target_file."""
        pass

    @override
    def put(
        self,
        config_file: str,
        key_path: str,
        val: any,
        sep="/",
        output_type: OutputType = OutputType.file,
        inline_array: bool = False,
        output_file: str = None,
    ) -> Dict[str, any]:
        """Add or update the value of a key (or content of array at index / key) if it exists."""
        data = self.load(config_file)
        if len(key_path.split(sep)) > 2:
            raise OpenSearchPluginError(
                "SimplePropertiesSetter.put: key path acceptable up most depth=2."
            )

        if len(key_path.split(sep)) == 1:
            if isinstance(data[key_path.split(sep)[0]], list):
                data[key_path.split(sep)[0]].append(val)
            else:
                data[key_path.split(sep)[0]] = [val]
        else:
            if key_path.split(sep)[0] not in data.keys() or isinstance(
                data[key_path.split(sep)[0]], list
            ):
                data[key_path.split(sep)[0]] = {}
            d = data[key_path.split(sep)[0]]
            if key_path.split(sep)[1] not in d.keys():
                d[key_path.split(sep)[1]] = {}

            if isinstance(d[key_path.split(sep)[1]], list):
                d[key_path.split(sep)[1]].append(val)
            else:
                d[key_path.split(sep)[1]] = [val]

        self.dump(
            data,
            output_type,
            f"{self.base_path}{config_file}" if output_file is None else output_file,
        )
        return data

    @override
    def delete(
        self,
        config_file: str,
        key_path: str,
        sep="/",
        output_type: OutputType = OutputType.file,
        output_file: str = None,
    ) -> Dict[str, any]:
        """Delete the value of a key (or content of array at index / key) if it exists."""
        data = self.load(config_file)
        if len(key_path.split(sep)) > 2:
            raise OpenSearchPluginError(
                "SimplePropertiesSetter.put: key path acceptable up most depth=2."
            )

        if len(key_path.split(sep)) == 1:
            del data[key_path]
        else:
            del data[key_path.split(sep)[0]][key_path.split(sep)[1]]
            if len(data[key_path.split(sep)[0]].values()) == 0:
                del data[key_path.split(sep)[0]]

        self.dump(
            data,
            output_type,
            f"{self.base_path}{config_file}" if output_file is None else output_file,
        )
        return data

    def replace(
        self,
        config_file: str,
        old_val: str,
        new_val: any,
        regex: bool = False,
        output_type: OutputType = OutputType.file,
        output_file: str = None,
    ) -> None:
        """Replaces the matches for the old_val. Recommended to use delete/put instead."""
        return


class SecurityPolicySetter(SimplePropertiesSetter):
    """Represents the plugin's security policy file."""

    @override
    def load(self, config_file: str) -> Dict[str, any]:
        """Load the content of a file."""
        path = f"{self.base_path}{config_file}"

        if not exists(path):
            raise FileNotFoundError(f"{path} not found.")

        with open(path) as f:
            plugin = f.read()
        # The text has the format:
        # // or /**/ represent single- and multi-line comments
        # grant {...}; represent the rules to consider
        # Each rule has the format:
        #   permission <permission-classname> "<param1>", ..., "paramN";
        # param1 is the relevant identifier (i.e. who in the plugin should have access)
        # Therefore, param1 will be the dict key

        # Parse the grant {...}
        granted = re.findall(r"grant[ \t]+{(.*?)};", plugin, flags=re.DOTALL | re.MULTILINE)[0]
        # Parse each rule
        r = re.findall(r"permission[ \t]+(.*?);", granted)
        data = {}
        for el in r:
            d = re.findall(r'[ \t]+"(.*?)"', el)
            if not el.split(" ")[0] in data.keys():
                data[el.split(" ")[0]] = {}
            data[el.split(" ")[0]][d[0]] = d[1:] if isinstance(d, list) else [d]

        return data

    @override
    def dump(self, data: Dict[str, any], output_type: OutputType, target_file: str):
        """Write the data on the corresponding "output_type" stream."""
        if not data:
            return
        path = f"{self.base_path}{target_file}"

        content = (
            "grant {\n"
            + ";\n".join(
                [
                    "  permission "
                    + k
                    + " "
                    + ", ".join([f'"{param1}"'] + [f'"{e}"' for e in param_list])
                    for k, v in data.items()
                    for param1, param_list in v.items()
                ]
            )
            + ";\n};"
        )

        if output_type in [OutputType.console, OutputType.all]:
            logger.info(f"Policy Setter content: {content}")

        if output_type in [OutputType.file, OutputType.all]:
            with open(path, mode="w") as f:
                f.write(content)


class PluginPropertiesSetter(SimplePropertiesSetter):
    """Represents the plugin's properties file."""

    @override
    def load(self, config_file: str) -> Dict[str, any]:
        """Load the content of the file."""
        path = f"{self.base_path}{config_file}"

        if not exists(path):
            raise FileNotFoundError(f"{path} not found.")

        with open(path) as f:
            p1 = f.read()
        # The text has the format:
        # #, // or /**/ represent single- and multi-line comments
        # PROPERTY = PARAMS # represents the actual contents of the configuration file

        # Remove the comments
        p2 = "".join(re.sub(r"/\*.*?\*/", "", p1, flags=re.DOTALL | re.MULTILINE))
        p3 = [
            re.sub(r"(#.*$|//.*$)", "", el)
            for el in p2.split("\n")
            if len(re.sub(r"(#.*$|//.*$)", "", el)) > 0
        ]
        # Parse properties
        props = {}
        for p in p3:
            r = re.findall(r"[ \t]*(.*?)[ \t]*=[ \t]*(.*$)", p)[0]
            props[r[0]] = [r[1]] if len(r[1]) > 0 else []

        return props

    @override
    def dump(self, data: Dict[str, any], output_type: OutputType, target_file: str):
        """Write the data on the corresponding "output_type" stream."""
        if not data:
            return
        path = f"{self.base_path}{target_file}"

        content = "\n".join([f"{k}={v[0] if len(v) > 0 else ''}" for k, v in data.items()])

        if output_type in [OutputType.console, OutputType.all]:
            logger.info(f"Plugin Properties Setter content: {content}")

        if output_type in [OutputType.file, OutputType.all]:
            with open(path, mode="w") as f:
                f.write(content)

    @override
    def put(
        self,
        config_file: str,
        key_path: str,
        val: any,
        sep="/",
        output_type: OutputType = OutputType.file,
        inline_array: bool = False,
        output_file: str = None,
    ) -> Dict[str, any]:
        """Add or update the value of a key (or content of array at index / key) if it exists."""
        data = self.load(config_file)
        if len(key_path.split(sep)) > 1:
            raise OpenSearchPluginError(
                "PluginPropertiesSetter.put: key path acceptable up most depth=2."
            )

        data[key_path] = [val]
        self.dump(
            data,
            output_type,
            f"{self.base_path}{config_file}" if output_file is None else output_file,
        )
        return data
