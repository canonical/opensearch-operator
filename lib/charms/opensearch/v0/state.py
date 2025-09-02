# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Objects representing the state of OpenSearchBaseCharm."""

import logging
from typing import TYPE_CHECKING, Dict

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.models import PluginConfigType, PluginSecret
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
    def plugin_secrets(self) -> Dict[str, PluginSecret]:
        """Returns plugin secrets this app is tracking"""
        plugins = self.relation_data.get_object(self.scope, "plugin_secrets") or {}
        return {label: PluginSecret.from_dict(plugin) for label, plugin in plugins.items()}

    def add_plugin_secret(self, label: str, plugin: PluginSecret) -> None:
        """Adds plugin secret being tracked by app"""
        plugin_secrets = self.plugin_secrets
        plugin_secrets[label] = plugin
        self.relation_data.put_object(self.scope, "plugin_secrets", plugin_secrets)

    def remove_plugin_secret(self, label: str) -> None:
        """Remove plugin secret no longer being tracked by app"""
        plugin_secrets = self.plugin_secrets
        if label in plugin_secrets:
            del plugin_secrets[label]
            self.relation_data.put_object(self.scope, "plugin_secrets", plugin_secrets)


class OpenSearchUnit:
    """State/Relation data collection for an opensearch node (juju unit)."""

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ):
        self.scope = Scope.UNIT
        self.relation_data = RelationDataStore(charm, PeerRelationName)

    @property
    def plugin_secrets(self) -> Dict[str, PluginConfigType]:
        """Returns plugin secret labels this unit is tracking"""
        secret_labels = self.relation_data.get_object(self.scope, "plugin_secret_labels") or {}
        return {label: PluginConfigType(typ) for label, typ in secret_labels.items()}

    def add_plugin_secret_label(self, label: str, typ: PluginConfigType) -> None:
        """Adds plugin secret being tracked by unit"""
        plugin_secrets = self.plugin_secrets
        plugin_secrets[label] = typ
        self.relation_data.put_object(self.scope, "plugin_secret_labels", plugin_secrets)

    def remove_plugin_secret_label(self, label: str) -> None:
        """Remove plugin secret no longer being tracked by unit"""
        plugin_secrets = self.plugin_secrets
        if label in plugin_secrets:
            del plugin_secrets[label]
            self.relation_data.put_object(self.scope, "plugin_secret_labels", plugin_secrets)


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
