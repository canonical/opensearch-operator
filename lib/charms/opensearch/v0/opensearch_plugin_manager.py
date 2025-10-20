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
from typing import TYPE_CHECKING, Dict, List, Optional

from charms.opensearch.v0.constants_charm import PeerRelationName, SmtpRelationInvalid
from charms.opensearch.v0.helper_charm import Status, diff
from charms.opensearch.v0.models import DeploymentType, PluginConfigInfo
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.smtp_integrator.v0.smtp import DEFAULT_RELATION_NAME as SMTP_RELATION
from charms.smtp_integrator.v0.smtp import SmtpRequires
from ops import BlockedStatus
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

SmtpNoRelationData = "No relation data found. Please check the relation with smtp-integrator."
SmtpMissingRequiredParameters = "Parameters missing from smtp-integrator: {}."


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
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            logger.debug("Deployment not ready. Deferring event.")
            event.defer()
            return

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(SmtpRelationInvalid), app=True)
            return

        if not self.charm.opensearch.is_started():
            # node must be reachable to reload settings after adding keys
            event.defer()
            return

        # return if no relation data
        if not (parameters := self.smtp.get_relation_data()):
            logger.debug("Missing relation data from %s", self.relation_name)
            self.charm.status.set(BlockedStatus(SmtpNoRelationData))
            return

        self.charm.status.clear(SmtpNoRelationData)

        # validate data
        required_params = ["user", "password"]
        if missing_parameters := [p for p in required_params if not getattr(parameters, p)]:
            msg = SmtpMissingRequiredParameters.format(", ".join(missing_parameters))
            logger.error(msg)
            self.charm.status.set(BlockedStatus(msg))
            return

        self.charm.status.clear(
            SmtpMissingRequiredParameters, pattern=Status.CheckPattern.Interpolated
        )

        # create keys for keystore
        user = parameters.user
        entries = {
            f"opensearch.notifications.core.email.{user}.username": f"{user}",
            f"opensearch.notifications.core.email.{user}.password": f"{parameters.password}",
        }

        self.charm.keystore.add_entries(entries)
        if not self.charm.keystore.reload():
            logger.debug("Could not reload secure settings. Deferring event.")
            event.defer()
            return

        # store keys to remove later
        self.charm.plugin_manager.put_plugin_config(
            scope=Scope.UNIT,
            label=self.secret_label,
            cleanup={"keys": list(entries.keys())},
        )
        if not self.charm.unit.is_leader():
            return

        self.charm.secrets.put(Scope.APP, self.secret_label, json.dumps({"keys": entries}))
        secret_id = self.charm.secrets.get_secret_id(Scope.APP, self.secret_label)
        self.charm.plugin_manager.put_plugin_config(
            scope=Scope.APP,
            label=self.secret_label,
            secret_id=secret_id,
            relation_name=self.relation_name,
        )

        # if unit is main orchestrator leader, transfer keys to subclusters
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_smtp_credentials_gone(self, event) -> None:
        """Removes secret when credentials are gone"""
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            logger.debug("Deployment not ready. Deferring event.")
            event.defer()
            return

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.clear(SmtpRelationInvalid, app=True)
            return

        plugin_config = self.charm.state.unit.plugin_config_info.get(self.secret_label)
        keys = plugin_config.cleanup.get("keys")

        self.charm.keystore.remove_entries(keys)

        if not self.charm.keystore.reload():
            logger.debug("Could not reload secure settings. Deferring event.")
            event.defer()
            return

        self.charm.plugin_manager.remove_plugin_config(scope=Scope.UNIT, label=self.secret_label)

        if not self.charm.unit.is_leader():
            return

        try:
            self.charm.secrets.delete(Scope.APP, self.secret_label)
            self.charm.plugin_manager.remove_plugin_config(
                scope=Scope.APP, label=self.secret_label
            )

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

        content = event.secret.get_content(refresh=True)
        if not (raw := content.get(self.secret_label)):
            logger.warning("Secret %s has no %s payload", event.secret.label, self.secret_label)
            return

        try:
            plugin_config = json.loads(raw)
        except json.JSONDecodeError:
            logger.error("Malformed JSON in secret %s", event.secret.label)
            return

        if not (keys := plugin_config.get("keys")):
            return

        # the keys to remove (user) may be changed here, add them to removal info for cleanup later
        self.charm.plugin_manager.put_plugin_config(
            scope=Scope.UNIT,
            label=self.secret_label,
            cleanup={"keys": list(keys.keys())},
        )

        self.charm.keystore.add_entries(keys)
        if not self.charm.keystore.reload():
            logger.debug("Could not reload secure settings. Deferring event.")
            event.defer()
            return


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
            if not (raw := content.get(label)):
                continue

            try:
                plugin_config = json.loads(raw)
            except json.JSONDecodeError:
                logger.error("Invalid JSON in secret for label %s", label)
                continue

            keys_to_add = plugin_config.get("keys")

            # store on unit for later removal (only keys needed and not values)
            self.charm.plugin_manager.put_plugin_config(
                scope=Scope.UNIT, label=label, cleanup={"keys": list(keys_to_add.keys())}
            )
            self.charm.keystore.add_entries(keys_to_add)

        for label in removed:
            # this unit should delete the keys it wrote as the app secret has been removed
            cleanup = unit_plugins[label].cleanup
            for key, items in cleanup.items():
                if key == "keys":
                    self.charm.keystore.remove_entries(items)

        # reload keystore
        if not self.charm.keystore.reload():
            logger.debug("Could not reload secure settings. Deferring event.")
            event.defer()
            return

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
        plugin_config = plugins.get(label) or PluginConfigInfo(
            relation_name=relation_name,
            secret_id=secret_id,
        )
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
