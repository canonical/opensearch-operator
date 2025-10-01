# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Objects representing the state of OpenSearchBaseCharm."""

import logging
from typing import TYPE_CHECKING, Dict

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.models import (
    PluginConfigInfo,
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
    def plugin_config_info(self) -> Dict[str, PluginConfigInfo]:
        """Returns configuration information for plugins this app is managing"""
        plugin_config_info = self.relation_data.get_object(self.scope, "plugin_config_info") or {}
        return {
            label: PluginConfigInfo.from_dict(plugin)
            for label, plugin in plugin_config_info.items()
        }


class OpenSearchUnit:
    """State/Relation data collection for an opensearch node (juju unit)."""

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ):
        self.scope = Scope.UNIT
        self.relation_data = RelationDataStore(charm, PeerRelationName)

    @property
    def plugin_config_info(self) -> Dict[str, PluginConfigInfo]:
        """Returns configuration information for plugins this unit is managing"""
        plugin_configs = self.relation_data.get_object(self.scope, "plugin_config_info") or {}
        return {label: PluginConfigInfo.from_dict(info) for label, info in plugin_configs.items()}


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
