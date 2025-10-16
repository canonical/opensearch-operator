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
from charms.opensearch.v0.helper_charm import Status, diff
from charms.opensearch.v0.helper_plugins import (
    decode_plugin_secret_content,
    remove_plugin_secret,
    store_plugin_secret,
)
from charms.opensearch.v0.models import (
    AzureRelData,
    GcsRelData,
    ObjectStorageConfig,
    PluginConfigInfo,
    S3RelData,
)
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.smtp_integrator.v0.smtp import DEFAULT_RELATION_NAME as SMTP_RELATION
from charms.smtp_integrator.v0.smtp import SmtpRequires
from ops import BlockedStatus
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

        store_plugin_secret(
            self.charm,
            content={"keys": entries},
            label=self.secret_label,
            relation_name=self.relation_name,
        )

        # if unit is main orchestrator leader, transfer keys to subclusters
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_smtp_credentials_gone(self, event) -> None:
        """Removes secret when credentials are gone"""
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

        remove_plugin_secret(self.charm, self.secret_label)
        # if unit is main orchestrator leader, remove secrets transferred to subclusters
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_secret_changed(self, event) -> None:
        """Handles secret changes"""
        label = self.charm.secrets.label(Scope.APP, self.secret_label)
        if label != event.secret.label:
            return

        content = event.secret.get_content(refresh=True)
        if not (plugin_config := decode_plugin_secret_content(content, label)):
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
        # Only sub-clusters consume secrets from the main provider
        if not self.charm.opensearch_peer_cm.is_consumer(of="main"):
            return

        app_plugins = self.charm.state.app.plugin_config_info
        unit_plugins = self.charm.state.unit.plugin_config_info
        added, removed = diff(app_plugins.keys(), unit_plugins.keys())
        logger.debug("[plugins/peer] added=%s removed=%s", list(added), list(removed))

        # add/update
        wrote_keys = False
        for label in added:
            plugin = app_plugins[label]
            logger.info(
                "[plugins/peer] processing added label=%s secret_id=%s", label, plugin.secret_id
            )
            if not plugin.secret_id:
                continue

            # start locally tracking secret and write transferred keys to keystore
            content = self.charm.secrets.get_tracked_secret(
                plugin.secret_id, Scope.APP, label
            ).get_content()

            if not (plugin_payload := decode_plugin_secret_content(content, label)):
                continue

            keys_to_add = plugin_payload.get("keys") or {}
            repo = plugin_payload.get("repo") or {}
            tls_ca_chain = plugin_payload.get("tlscachain")

            # store on unit for later removal (only key names)
            if keys_to_add:
                self.charm.plugin_manager.put_plugin_config(
                    scope=Scope.UNIT, label=label, cleanup={"keys": list(keys_to_add.keys())}
                )
                self.charm.keystore.add_entries(keys_to_add)
                wrote_keys = True

            # store S3 CA (optional)
            if repo.get("type") == "s3" and tls_ca_chain:
                self.charm.snapshots_manager.store_s3_ca(tls_ca_chain)

            # create local marker so actions can detect storage type
            if repo.get("type") == "s3":
                obj_type_marker = "s3-pcluster"
            elif repo.get("type") == "azure":
                obj_type_marker = "azure-pcluster"
            # elif repo.get("type") == "gcs":
            #    obj_type_marker = "gcs-pcluster"
            else:
                obj_type_marker = None

            if obj_type_marker:
                self.charm.peers_data.put(
                    Scope.UNIT, "snapshot-object-storage-type", obj_type_marker
                )
                logger.info("[plugins/peer] set marker=%s and ensured repo", obj_type_marker)

        # reload keystore once after all adds/removes
        if wrote_keys:
            if not self.charm.keystore.reload():
                logger.debug("Could not reload secure settings. Deferring event.")
                event.defer()
                return
            logger.debug("[plugins/peer] keystore reloaded successfully")

        # remove
        for label in removed:
            # delete any keys this unit wrote previously
            cleanup = unit_plugins[label].cleanup
            for key, items in cleanup.items():
                if key == "keys" and items:
                    self.charm.keystore.remove_entries(items)

        # reload keystore after removals
        if not self.charm.keystore.reload():
            logger.debug("Could not reload secure settings. Deferring event.")
            event.defer()
            return

        # finalize cleanup metadata after successful reload
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
