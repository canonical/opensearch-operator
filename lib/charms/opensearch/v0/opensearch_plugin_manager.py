# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import logging
from typing import TYPE_CHECKING, Dict, List, Optional

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.helper_charm import diff
from charms.opensearch.v0.helper_plugins import (
    decode_plugin_secret_content,
)
from charms.opensearch.v0.models import PluginConfigInfo
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.framework import Object

# The unique Charmhub library identifier, never change it
LIBID = "da838485175f47dbbbb83d76c07cab4c"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm


class OpenSearchPluginEvents(Object):
    """Events handler for OpenSearch plugin events"""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "plugins")
        self.charm = charm
        self.framework.observe(
            self.charm.on[PeerRelationName].relation_changed, self._on_peer_relation_changed
        )

    def _on_peer_relation_changed(self, event):  # noqa: C901
        """Handle plugin secret-related peer relation changes."""
        # if this is a subcluster, all units must add plugin keys from secrets to their keystores
        if not self.charm.opensearch_peer_cm.is_consumer(of="main"):
            return

        app_plugins = self.charm.state.app.plugin_config_info
        unit_plugins = self.charm.state.unit.plugin_config_info
        added, removed = diff(app_plugins.keys(), unit_plugins.keys())
        for label in added:
            plugin = app_plugins[label]
            if not plugin.secret_id:
                continue

            # start locally tracking secret and write transferred keys to keystore
            content = self.charm.secrets.get_tracked_secret(
                plugin.secret_id, Scope.APP, label
            ).get_content()
            if not (plugin_config := decode_plugin_secret_content(content, label)):
                continue

            keys_to_add = plugin_config.get("keys")

            self.charm.keystore_manager.put_entries(keys_to_add)
            cleanup = {"keys": list(keys_to_add.keys())}
            # store on unit for later removal (only keys needed and not values)
            self.charm.plugin_manager.put_plugin_config(
                scope=Scope.UNIT, label=label, cleanup=cleanup
            )

        for label in removed:
            # this unit should delete the keys it wrote as the app secret has been removed
            cleanup = unit_plugins[label].cleanup
            for key, items in cleanup.items():
                if key == "keys":
                    self.charm.keystore_manager.remove_entries(items)

        # reload keystore
        self.charm.opensearch_keystore_events.reload_event.emit()

        for label in removed:
            self.charm.plugin_manager.remove_plugin_config(scope=Scope.UNIT, label=label)


class OpenSearchPluginManager:
    """Manager to persist OpenSearch plugin configuration information"""

    def __init__(self, state):
        self._state = state

    def put_plugin_config(
        self,
        scope: Scope,
        label: str,
        secret_id: Optional[str] = None,
        relation_name: Optional[str] = None,
        cleanup: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        """Adds plugin configuration information to peer relation data"""
        state = self._state.app if scope == Scope.APP else self._state.unit
        plugins = state.plugin_config_info
        plugin_config = plugins.get(label) or PluginConfigInfo()
        plugin_config.relation_name = relation_name
        plugin_config.secret_id = secret_id
        if cleanup:
            plugin_config.add_cleanup_items(cleanup)
        plugins[label] = plugin_config
        state.relation_data.put_object(scope, "plugin_config_info", plugins)

    def remove_plugin_config(self, scope: Scope, label: str) -> None:
        """Removes plugin configuration information from peer relation data"""
        state = self._state.app if scope == Scope.APP else self._state.unit
        plugins = state.plugin_config_info
        if label in plugins:
            del plugins[label]
            if not plugins:
                state.relation_data.delete(scope, "plugin_config_info")
                return
            state.relation_data.put_object(scope, "plugin_config_info", plugins)
