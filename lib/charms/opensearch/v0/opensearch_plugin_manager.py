# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import logging
import re
from typing import TYPE_CHECKING, Dict, List, Optional

from charms.opensearch.v0.constants_charm import (
    SMTP_SECRET_LABEL,
    PeerRelationName,
    SmtpMissingRequiredParameters,
    SmtpNoRelationData,
    SmtpRelationInvalid,
    SmtpWaitingRecipients,
)
from charms.opensearch.v0.helper_charm import Status, diff
from charms.opensearch.v0.helper_plugins import (
    decode_plugin_secret_content,
    remove_plugin_secret,
    store_plugin_secret,
)
from charms.opensearch.v0.models import DeploymentType, PluginConfigInfo
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.smtp_integrator.v0.smtp import DEFAULT_RELATION_NAME as SMTP_RELATION
from charms.smtp_integrator.v0.smtp import SmtpRequires
from ops import BlockedStatus, WaitingStatus
from ops.framework import Object

# The unique Charmhub library identifier, never change it
LIBID = "da838485175f47dbbbb83d76c07cab4c"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm


class SmtpEvents(Object):
    """Events handler for smtp events"""

    relation_name = SMTP_RELATION

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "plugin:notifications")
        self.charm = charm
        self.smtp = SmtpRequires(self.charm, self.relation_name)

        self.framework.observe(self.smtp.on.smtp_data_available, self._on_smtp_credentials_changed)
        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken, self._on_smtp_credentials_gone
        )
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    @staticmethod
    def _label(relation_id: int) -> str:
        """Return label for this relation.

        Args:
            relation_id: relation id

        Returns:
            relation label
        """
        return f"{SMTP_SECRET_LABEL}-{relation_id}"

    @staticmethod
    def _recipient_group_id(sender_id: str) -> str:
        """Return recipient group id for this relation.

        Args:
            sender_id: sender id

        Returns:
            sender group id
        """
        return f"{sender_id}_recipients"

    @staticmethod
    def _email_channel_id(sender_id: str) -> str:
        """Return email channel id for this relation.

        Args:
            sender_id: sender id

        Returns:
            email channel id
        """
        return f"{sender_id}_email-channel"

    @staticmethod
    def _sender_id_from_email(sender_email: str) -> str:
        """Return sender id for this relation.

        Args:
            sender_email: sender email

        Returns:
            sender id
        """
        s = sender_email.strip().lower()
        s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
        return f"smtp-sender-{s}"

    def _has_duplicate_sender_emails(self) -> Optional[str]:
        """Return duplicate sender email if exists, else None.

        Returns:
            Duplicate sender email if exists, else None
        """
        seen: dict[str, int] = {}
        for rel in self.charm.model.relations[self.relation_name]:
            try:
                data = self.smtp.get_relation_data_from_relation(rel)
            except Exception:
                # ignore the error, handler will take care of it
                continue
            if not data or not data.smtp_sender:
                continue
            sender = str(data.smtp_sender)
            if sender in seen and seen[sender] != rel.id:
                return sender
            seen[sender] = rel.id
        return None

    def _on_smtp_credentials_changed(self, event) -> None:  # noqa: C901
        """Configure notifications sender/group/channel and keystore creds for this relation.

        Args:
            event: Smtp credentials available event
        """
        parameters = None
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            logger.debug("Deployment not ready. Deferring event.")
            event.defer()
            return

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(SmtpRelationInvalid), app=True)
            return

        if not self.charm.opensearch.is_started():
            # service must be reachable
            event.defer()
            return

        try:
            parameters = self.smtp.get_relation_data_from_relation(event.relation)
        except Exception as exc:
            msg = f"Could not read smtp relation data: {exc}"
            logger.error(msg)
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(msg), app=True)
                return

            if not parameters:
                if self.charm.unit.is_leader():
                    self.charm.status.set(BlockedStatus(SmtpNoRelationData), app=True)
                    return
        if self.charm.unit.is_leader():
            self.charm.status.clear(SmtpNoRelationData, app=True)

        missing = []
        if not parameters.smtp_sender:
            missing.append("smtp_sender")
        if not parameters.user:
            missing.append("user")
        if not parameters.password:
            missing.append("password")
        if not parameters.host:
            missing.append("host")
        if not parameters.port:
            missing.append("port")
        if not parameters.transport_security:
            missing.append("transport_security")

        if missing:
            msg = SmtpMissingRequiredParameters.format(", ".join(missing))
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(msg), app=True)
                return

        if self.charm.unit.is_leader():
            self.charm.status.clear(
                SmtpMissingRequiredParameters, pattern=Status.CheckPattern.Interpolated, app=True
            )

        duplicated_sender_emails = self._has_duplicate_sender_emails()
        if duplicated_sender_emails:
            if self.charm.unit.is_leader():
                self.charm.status.set(
                    BlockedStatus(
                        f"Duplicate SMTP sender email across smtp relations: {duplicated_sender_emails}"
                    ),
                    app=True,
                )
                return
        else:
            # clear any previous duplicate warning
            if self.charm.unit.is_leader():
                self.charm.status.clear(
                    "Duplicate SMTP sender email across smtp relations:",
                    app=True,
                    pattern=Status.CheckPattern.Start,
                )

        sender_email = str(parameters.smtp_sender)
        sender_id = self._sender_id_from_email(sender_email)
        label = self._label(event.relation.id)
        group_id = self._recipient_group_id(sender_id)
        channel_id = self._email_channel_id(sender_id)

        # create/update SMTP sender config
        if self.charm.unit.is_leader():
            self.charm.notifications.apply_smtp_sender(
                sender_id=sender_id,
                host=parameters.host,
                port=parameters.port,
                transport_security=parameters.transport_security,
                from_address=sender_email,
            )

        # store keystore creds on every unit
        entries = {
            f"opensearch.notifications.core.email.{sender_id}.username": parameters.user,
            f"opensearch.notifications.core.email.{sender_id}.password": parameters.password,
        }
        self.charm.keystore_manager.put_entries(entries)

        # reload secure settings
        if not self.charm.keystore_manager.reload():
            logger.debug("Could not reload secure settings. Deferring event.")
            event.defer()
            return

        # store cleanup info per relation
        cleanup = {
            "keys": list(entries.keys()),
            "notification_config_ids": [sender_id, group_id, channel_id],
        }
        self.charm.plugin_manager.put_plugin_config(scope=Scope.UNIT, label=label, cleanup=cleanup)

        # leader stores secret for subclusters for per relation
        if self.charm.unit.is_leader():
            store_plugin_secret(
                self.charm,
                content={
                    "keys": entries,
                    "notification_config_ids": cleanup["notification_config_ids"],
                },
                label=label,
                relation_name=self.relation_name,
            )

            # create recipient group and email channel if recipients are provided
            if parameters.recipients:
                self.charm.notifications.apply_email_group(
                    group_id=group_id,
                    recipients=[str(r) for r in parameters.recipients],
                )
                self.charm.notifications.apply_email_channel(
                    channel_id=channel_id,
                    sender_id=sender_id,
                    email_group_ids=[group_id],
                    fallback_recipients=[],
                )
                self.charm.status.clear(SmtpWaitingRecipients, app=True)
            if self.charm.unit.is_leader() and not parameters.recipients:
                self.charm.status.set(WaitingStatus(SmtpWaitingRecipients), app=True)

            # propagate to subclusters if this is the main provider
            if self.charm.opensearch_peer_cm.is_provider(typ="main"):
                self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_smtp_credentials_gone(self, event) -> None:  # noqa: C901
        """Cleanup for a broken smtp relation (relation-scoped).

        Args:
            event: Smtp relation broken event
        """
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            logger.debug("Deployment not ready. Deferring event.")
            event.defer()
            return

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.clear(SmtpRelationInvalid, app=True)
            return

        label = self._label(event.relation.id)

        plugin_config = self.charm.state.unit.plugin_config_info.get(label)
        if not plugin_config:
            return

        keys = plugin_config.cleanup.get("keys", [])
        config_ids = plugin_config.cleanup.get("notification_config_ids", [])

        if keys:
            self.charm.keystore_manager.remove_entries(keys)

        if not self.charm.keystore_manager.reload():
            logger.debug("Could not reload secure settings. Deferring event.")
            event.defer()
            return

        self.charm.plugin_manager.remove_plugin_config(scope=Scope.UNIT, label=label)

        if not self.charm.unit.is_leader():
            return

        # remove secrets and OpenSearch configs created by this relation
        if self.charm.unit.is_leader():
            remove_plugin_secret(self.charm, label)
            # delete channel first, then group, then sender
            for config_id in reversed(config_ids):
                try:
                    self.charm.notifications.delete_config(config_id)
                except Exception:
                    logger.exception("Failed deleting notifications config %s", config_id)

        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_secret_changed(self, event) -> None:
        """Handles secret changes (support multiple smtp relations).

        Args:
            event: Secret event
        """
        if SMTP_SECRET_LABEL not in event.secret.label:
            return

        content = event.secret.get_content(refresh=True)

        m = re.search(r"(plugin-notifications-\d+)", event.secret.label)
        if not m:
            return
        label = m.group(1)

        if not (plugin_config := decode_plugin_secret_content(content, label)):
            return

        keys = plugin_config.get("keys")
        if not keys:
            return

        self.charm.plugin_manager.put_plugin_config(
            scope=Scope.UNIT,
            label=label,
            cleanup={"keys": list(keys.keys())},
        )

        self.charm.keystore_manager.put_entries(keys)
        if not self.charm.keystore_manager.reload():
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
