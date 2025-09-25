# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import json
import logging
from typing import TYPE_CHECKING, List

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.helper_charm import diff
from charms.opensearch.v0.models import PluginConfigInfo, PluginConfigType
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.smtp_integrator.v0.smtp import DEFAULT_RELATION_NAME as SMTP_RELATION
from charms.smtp_integrator.v0.smtp import SmtpRequires
from ops.framework import Object
from ops.model import SecretNotFoundError

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

SMTP_SECRET_LABEL = "plugin-notifications"


class SmtpEvents(Object):
    """Events handler for smtp events"""

    relation_name = SMTP_RELATION
    secret_label = SMTP_SECRET_LABEL

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "plugin:notifications")
        self.charm = charm
        self.smtp = SmtpRequires(self.charm, self.relation_name)

        self.framework.observe(self.smtp.on.smtp_data_available, self._on_smtp_credentials_changed)
        self.framework.observe(self.charm.on.smtp_relation_broken, self._on_smtp_credentials_gone)
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_smtp_credentials_changed(self, event) -> None:
        """Creates secret containing key, value pairs for keystore"""
        if not self.charm.opensearch.is_started():
            # node must be reachable to reload settings after adding keys
            event.defer()
            return

        # return if no relation data
        if not (parameters := self.smtp.get_relation_data()):
            logger.debug("Missing relation %s", self.relation_name)
            return

        # validate data
        required_params = ["user", "password"]
        if missing_parameters := [p for p in required_params if not getattr(parameters, p)]:
            logger.error("Parameters missing from smtp-intgrator: %s" % missing_parameters)
            return

        # create keys for keystore
        user = parameters.user
        entries = {
            f"opensearch.notifications.core.email.{user}.username": f"{user}",
            f"opensearch.notifications.core.email.{user}.password": f"{parameters.password}",
        }

        self.charm.keystore.add_entries(entries)
        self.charm.keystore.reload()

        self.charm.plugin_manager.put_plugin_config_removal_info(
            self.secret_label, PluginConfigType.KEYS, list(entries.keys())
        )
        if not self.charm.unit.is_leader():
            return

        self.charm.secrets.put(Scope.APP, self.secret_label, json.dumps(entries))
        secret_id = self.charm.secrets.get_secret_id(Scope.APP, self.secret_label)
        self.charm.plugin_manager.put_plugin_config_info(
            self.secret_label,
            secret_id=secret_id,
            relation_name=self.relation_name,
            typ=PluginConfigType.KEYS,
        )

        # if unit is main orchestrator leader, transfer keys to subclusters
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_smtp_credentials_gone(self, event) -> None:
        """Removes secret when credentials are gone"""
        removal_info = self.charm.state.unit.plugin_config_removal_info.get(self.secret_label)
        keys = removal_info.removal_info

        self.charm.keystore.remove_entries(keys)
        self.charm.keystore.reload()
        self.charm.plugin_manager.remove_plugin_config_removal_info(self.secret_label)

        if not self.charm.unit.is_leader():
            return

        try:
            self.charm.secrets.delete(Scope.APP, self.secret_label)
            self.charm.plugin_manager.remove_plugin_config_info(self.secret_label)

            # if unit is main orchestrator leader, remove secrets transferred to subclusters
            if self.charm.opensearch_peer_cm.is_provider(typ="main"):
                self.charm.peer_cluster_provider.refresh_relation_data(event)
        except SecretNotFoundError:
            logger.debug("Can't find secret %s", self.secret_label)

    def _on_secret_changed(self, event) -> None:
        """Handles secret changes"""
        label = self.charm.secrets.label(Scope.APP, self.secret_label)
        if label != event.secret.label:
            return

        secret = event.secret.get_content(refresh=True)
        raw = secret.get(self.secret_label)
        keys = json.loads(raw)

        # the keys to remove (user) may be changed here, add them to removal info for cleanup later
        self.charm.plugin_manager.put_plugin_config_removal_info(
            self.secret_label, PluginConfigType.KEYS, list(keys.keys())
        )

        self.charm.keystore.add_entries(keys)
        self.charm.keystore.reload()


class OpenSearchPluginEvents(Object):
    """Events handler for OpenSearch plugin events"""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "plugins")
        self.charm = charm
        self.framework.observe(
            self.charm.on[PeerRelationName].relation_changed, self._on_peer_relation_changed
        )

    def _on_peer_relation_changed(self, event):
        """Handle plugin secret-related peer relation changes."""
        # if this is a subcluster, all units must add plugin keys from secrets to their keystores
        if not self.charm.opensearch_peer_cm.is_consumer(of="main"):
            return

        app_plugin_config_info = self.charm.state.app.plugin_config_info
        unit_plugin_config_info = self.charm.state.unit.plugin_config_removal_info
        added, removed = diff(app_plugin_config_info.keys(), unit_plugin_config_info.keys())
        for label in added:
            plugin = app_plugin_config_info[label]
            if not plugin.secret_id:
                continue

            # start locally tracking secret and write transferred keys to keystore
            keys_to_add = json.loads(
                self.charm.secrets.track_secret(plugin.secret_id, Scope.APP, label)
                .get_content()
                .get(label)
            )

            # store on unit for later removal (only keys needed and not values)
            self.charm.plugin_manager.put_plugin_config_removal_info(
                label, plugin.typ, list(keys_to_add.keys())
            )
            self.charm.keystore.add_entries(keys_to_add)

        for label in removed:
            # this unit should delete the keys it wrote as the app secret has been removed
            removal_info = unit_plugin_config_info[label]
            self.charm.keystore.remove_entries(removal_info.removal_info)
            self.charm.plugin_manager.remove_plugin_config_removal_info(label)

        # reload keystore
        self.charm.keystore.reload()


class OpenSearchPluginManager:
    """Manager to persist OpenSearch plugin configuration information"""

    def __init__(self, state):
        self._state = state

    def put_plugin_config_info(
        self, label: str, secret_id: str, relation_name: str, typ: PluginConfigType
    ) -> None:
        """Adds plugin secret being tracked by app"""
        plugin_config_info = self._state.app.plugin_config_info
        plugin_config_info[label] = PluginConfigInfo(
            relation_name=relation_name, secret_id=secret_id, typ=typ
        )
        self._state.app.relation_data.put_object(
            Scope.APP, "plugin_config_info", plugin_config_info
        )

    def remove_plugin_config_info(self, label: str) -> None:
        """Remove plugin secret no longer being tracked by app"""
        plugin_config_info = self._state.app.plugin_config_info
        if label in plugin_config_info:
            del plugin_config_info[label]
            self._state.app.relation_data.put_object(
                Scope.APP, "plugin_config_info", plugin_config_info
            )

    def put_plugin_config_removal_info(
        self, label: str, typ: PluginConfigType, content: List[str]
    ) -> None:
        """Adds plugin secret being tracked by unit"""
        plugin_configs = self._state.unit.plugin_config_removal_info
        plugin_config_info = plugin_configs.get(label) or PluginConfigInfo(typ=typ)
        plugin_config_info.add_removal_info(content)
        plugin_configs[label] = plugin_config_info
        self._state.unit.relation_data.put_object(Scope.UNIT, "plugin_config_info", plugin_configs)

    def remove_plugin_config_removal_info(self, label: str) -> None:
        """Remove plugin secret no longer being tracked by unit"""
        plugin_config_info = self._state.unit.plugin_config_removal_info
        if label in plugin_config_info:
            del plugin_config_info[label]
            self._state.unit.relation_data.put_object(
                Scope.UNIT, "plugin_config_info", plugin_config_info
            )
