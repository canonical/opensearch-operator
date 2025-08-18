# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Objects representing the state of OpenSearchBaseCharm."""

from functools import cached_property
import logging
from typing import TYPE_CHECKING, Any, Dict, Optional
from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.opensearch_internal_data import RelationDataStore, Scope
from charms.opensearch.v0.models import (
    Plugins,
    PeerClusterApp,
)

import json
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
    def plugin_secrets(self):
        """Returns plugin secrets this app is tracking"""
        return self.relation_data.get_object(self.scope, "plugin_secrets") or {}

    def add_plugin_secret(self, label: str, secret_id: str):
        """Adds plugin secret being tracked by app"""
        plugin_secrets = self.plugin_secrets
        plugin_secrets[label] = secret_id
        self.relation_data.put_object(self.scope, "plugin_secrets", plugin_secrets)

    def remove_plugin_secret(self, label: str):
        """Remove plugin secret no longer being tracked by app"""
        plugin_secrets = self.plugin_secrets
        if label in plugin_secrets:
            del plugin_secrets[label]
            self.relation_data.put_object(self.scope, "plugin_secrets", plugin_secrets)


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

