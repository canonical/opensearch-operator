# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Objects representing the state of OpenSearchBaseCharm."""

import logging
from typing import TYPE_CHECKING, Dict, List

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.models import (
    PluginConfigAddInfo,
    PluginConfigRemovalInfo,
    PluginConfigType,
)
from charms.opensearch.v0.opensearch_internal_data import RelationDataStore, Scope
from ops import Object

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class OpenSearchApp:
    """State/Relation data collection for an opensearch application."""

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ):
        self.scope = Scope.APP
        self.relation_data = RelationDataStore(charm, PeerRelationName)

    @property
    def plugin_config_info(self) -> Dict[str, PluginConfigAddInfo]:
        """Returns plugin secrets this app is tracking"""
        plugin_config_info = self.relation_data.get_object(self.scope, "plugin_config_info") or {}
        return {
            label: PluginConfigAddInfo.from_dict(plugin)
            for label, plugin in plugin_config_info.items()
        }

    def put_plugin_config_info(
        self, label: str, secret_id: str, relation_name: str, typ: PluginConfigType
    ) -> None:
        """Adds plugin secret being tracked by app"""
        plugin_config = self.plugin_config_info
        plugin_config[label] = PluginConfigAddInfo(
            relation_name=relation_name, secret_id=secret_id, typ=typ
        )
        self.relation_data.put_object(self.scope, "plugin_config_info", plugin_config)

    def remove_plugin_config_info(self, label: str) -> None:
        """Remove plugin secret no longer being tracked by app"""
        plugin_config_info = self.plugin_config_info
        if label in plugin_config_info:
            del plugin_config_info[label]
            self.relation_data.put_object(self.scope, "plugin_config_info", plugin_config_info)


class OpenSearchUnit:
    """State/Relation data collection for an opensearch node (juju unit)."""

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ):
        self.scope = Scope.UNIT
        self.relation_data = RelationDataStore(charm, PeerRelationName)

    @property
    def plugin_config_removal_info(self) -> Dict[str, PluginConfigRemovalInfo]:
        """Returns plugin secret labels this unit is tracking"""
        plugin_config_info = self.relation_data.get_object(self.scope, "plugin_config_info") or {}
        return {
            label: PluginConfigRemovalInfo.from_dict(info)
            for label, info in plugin_config_info.items()
        }

    def put_plugin_config_removal_info(
        self, label: str, typ: PluginConfigType, content: List[str]
    ) -> None:
        """Adds plugin secret being tracked by unit"""
        plugin_config_info = self.plugin_config_removal_info
        removal_info = plugin_config_info.get(label) or PluginConfigRemovalInfo(typ=typ)
        removal_info.add(content)
        plugin_config_info[label] = removal_info
        self.relation_data.put_object(self.scope, "plugin_config_info", plugin_config_info)

    def remove_plugin_config_removal_info(self, label: str) -> None:
        """Remove plugin secret no longer being tracked by unit"""
        plugin_config_info = self.plugin_config_removal_info
        if label in plugin_config_info:
            del plugin_config_info[label]
            self.relation_data.put_object(self.scope, "plugin_config_info", plugin_config_info)


class OpenSearchClusterState(Object):
    """Global state object for an opensearch cluster"""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(parent=charm, key="charm_state")
        self.charm = charm

    @property
    def app(self) -> OpenSearchApp:
        """Get state of the local opensearch app."""
        return OpenSearchApp(
            charm=self.charm,
        )

    @property
    def unit(self) -> OpenSearchUnit:
        """Get state of the local opensearch unit."""
        return OpenSearchUnit(
            charm=self.charm,
        )
