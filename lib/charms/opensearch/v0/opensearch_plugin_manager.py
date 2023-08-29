# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class."""

from typing import Dict, List

from charms.opensearch.v0.opensearch_plugins import OpenSearchPlugin
from ops.framework import Object
from ops.model import ActiveStatus, StatusBase

# The unique Charmhub library identifier, never change it
LIBID = "da838485175f47dbbbb83d76c07cab4c"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


OpenSearchPluginsAvailable = {}


class OpenSearchPluginManager:
    """Manages the currently enabled plugins."""

    def __init__(self, charm: Object):
        self._charm = charm

    @property
    def plugins(self) -> Dict[str, OpenSearchPlugin]:
        """Returns dict of installed plugins."""
        return {
            key: plugin_data["class"](key, self._charm, relname=plugin_data["relation-name"])
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
            else plugin_data["config-name"]: plugin_data["class"](
                key, self._charm, relname=plugin_data["relation-name"]
            )
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
