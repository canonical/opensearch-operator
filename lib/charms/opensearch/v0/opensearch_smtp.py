# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""SMTP integration for the OpenSearch charm.

SmtpEvents: handles the smtp-integrator relation (credentials available,
  relation broken, secret changed). Validates SMTP parameters, creates/updates
  OpenSearch notification configs and keystore entries, and cleans up on
  relation break.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from charms.data_platform_libs.v0.data_interfaces import SecretError
from charms.opensearch.v0.constants_charm import (
    SMTP_SECRET_LABEL,
    SMTPConfigurationError,
    SmtpDuplicateSender,
    SmtpMissingRequiredParameters,
    SmtpNoRelationData,
    SmtpRelationInvalid,
    SmtpWaitingRecipients,
)
from charms.opensearch.v0.helper_charm import Status
from charms.opensearch.v0.helper_plugins import (
    decode_plugin_secret_content,
)
from charms.opensearch.v0.models import DeploymentType
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_notifications import (
    NotificationsClientError,
)
from charms.smtp_integrator.v0.smtp import DEFAULT_RELATION_NAME as SMTP_RELATION
from charms.smtp_integrator.v0.smtp import SmtpDataAvailableEvent, SmtpRequires
from ops import BlockedStatus, WaitingStatus
from ops.charm import RelationBrokenEvent, SecretChangedEvent
from ops.framework import Object

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

    def _has_duplicate_sender_emails(self) -> str | None:
        """Return duplicate sender email if one exists, else None.

        Returns:
            The first duplicate sender email found, or None.
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

    def _on_smtp_credentials_changed(self, event: SmtpDataAvailableEvent) -> None:  # noqa: C901
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

        if not self.charm.opensearch.is_node_up():
            logger.debug("OpenSearch is not ready yet. Deferring event.")
            event.defer()
            return

        try:
            parameters = self.smtp.get_relation_data_from_relation(event.relation)
        except SecretError as exc:
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
        if not parameters.host:
            missing.append("host")
        if not parameters.port:
            missing.append("port")
        if not parameters.transport_security:
            missing.append("transport_security")
        if parameters.auth_type != "none":
            if not parameters.user:
                missing.append("user")
            if not parameters.password:
                missing.append("password")

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
                msg = SmtpDuplicateSender.format(", ".join(duplicated_sender_emails))
                self.charm.status.set(
                    BlockedStatus(msg),
                    app=True,
                )
                return
        else:
            # clear any previous duplicate warning
            if self.charm.unit.is_leader():
                self.charm.status.clear(
                    SmtpDuplicateSender,
                    pattern=Status.CheckPattern.Start,
                    app=True,
                )

        config = self.charm.notifications.get_smtp_config(parameters, event.relation.id)

        # If sender changed, remove old notification configs so one relation has one valid config
        if self.charm.unit.is_leader():
            if plugin_config := self.charm.state.unit.plugin_config_info.get(config.label):
                smtp_account_ids = plugin_config.cleanup.get("smtp_account_id")
                if smtp_account_ids and smtp_account_ids[0] != config.smtp_account_id:
                    old_id = smtp_account_ids[0]
                    channel_id = self.charm.notifications.email_channel_id(old_id)
                    group_id = self.charm.notifications.recipient_group_id(old_id)
                    for config_id in (channel_id, group_id, old_id):
                        try:
                            self.charm.notifications.delete_config(config_id)
                        except OpenSearchHttpError:
                            logger.exception(
                                "Failed deleting old notifications config %s", config_id
                            )

        # create/update SMTP sender config
        if self.charm.unit.is_leader():
            try:
                self.charm.notifications.put_smtp_sender(
                    smtp_account_id=config.smtp_account_id,
                    host=parameters.host,
                    port=parameters.port,
                    transport_security=config.transport_security,
                    from_address=config.sender_email,
                )
            except NotificationsClientError as e:
                logger.error(
                    "Failed to create SMTP sender with smtp_account_id: %s with Error: %s",
                    config.smtp_account_id,
                    str(e),
                )
                self.charm.status.set(
                    BlockedStatus(SMTPConfigurationError),
                    app=True,
                )
                event.defer()
                return

            self.charm.status.clear(SMTPConfigurationError, app=True)

        if parameters.auth_type != "none":
            # store keystore creds on every unit
            entries = {
                f"opensearch.notifications.core.email.{config.smtp_account_id}.username": parameters.user,
                f"opensearch.notifications.core.email.{config.smtp_account_id}.password": parameters.password,
            }
            self.charm.keystore_manager.put_entries(entries)

            # reload secure settings
            self.charm.opensearch_keystore_events.reload_event.emit()
            # store cleanup info per relation
            cleanup = {
                "keys": list(entries.keys()),
                "smtp_account_id": [config.smtp_account_id],
            }
            self.charm.plugin_manager.put_plugin_config(
                scope=Scope.UNIT, label=config.label, cleanup=cleanup
            )

            if self.charm.unit.is_leader():
                # leader stores secret for subclusters for per relation
                self.charm.store_plugin_secret(
                    content={
                        "keys": entries,
                        "smtp_account_id": cleanup["smtp_account_id"],
                    },
                    label=config.label,
                    relation_name=self.relation_name,
                )
        else:
            # No keystore entries for auth_type "none", still store smtp_account_id for cleanup
            self.charm.plugin_manager.put_plugin_config(
                scope=Scope.UNIT,
                label=config.label,
                cleanup={"smtp_account_id": [config.smtp_account_id]},
            )

        if not self.charm.unit.is_leader():
            return
        # create recipient group and email channel if recipients are provided
        if parameters.recipients:
            try:
                self.charm.notifications.put_email_group(
                    group_id=config.group_id,
                    recipients=[str(r) for r in parameters.recipients],
                )
                self.charm.notifications.put_email_channel(
                    channel_id=config.channel_id,
                    smtp_account_id=config.smtp_account_id,
                    email_group_ids=[config.group_id],
                    fallback_recipients=[],
                )
            except NotificationsClientError as e:
                logger.error(
                    "Failed to create SMTP email channel with group: %s with Error: %s",
                    config.group_id,
                    str(e),
                )
                self.charm.status.set(
                    BlockedStatus(SMTPConfigurationError),
                    app=True,
                )
                event.defer()
                return
            self.charm.status.clear(SmtpWaitingRecipients, app=True)
            self.charm.status.clear(SMTPConfigurationError, app=True)
        else:
            self.charm.status.set(WaitingStatus(SmtpWaitingRecipients), app=True)

        # propagate to subclusters if this is the main provider
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_smtp_credentials_gone(self, event: RelationBrokenEvent) -> None:  # noqa: C901
        """Cleanup for a broken smtp relation (relation-scoped).

        Args:
            event: RelationBrokenEvent
        """
        if self.charm.unit.is_leader():
            self.charm.status.clear(SmtpRelationInvalid, app=True)
            self.charm.status.clear(SMTPConfigurationError, app=True)
            self.charm.status.clear(SmtpNoRelationData, app=True)
            self.charm.status.clear(
                SmtpMissingRequiredParameters, pattern=Status.CheckPattern.Interpolated, app=True
            )

        label = self.charm.notifications.label(event.relation.id)

        if not (plugin_config := self.charm.state.unit.plugin_config_info.get(label)):
            return

        keys = plugin_config.cleanup.get("keys", [])
        smtp_account_ids = plugin_config.cleanup.get("smtp_account_id")

        if keys:
            self.charm.keystore_manager.remove_entries(keys)

        self.charm.opensearch_keystore_events.reload_event.emit()

        self.charm.plugin_manager.remove_plugin_config(scope=Scope.UNIT, label=label)

        if not self.charm.unit.is_leader():
            return

        # remove secrets and OpenSearch configs created by this relation
        self.charm.remove_plugin_secret(label)

        # Delete in dependency order: channel, then group, then smtp account
        smtp_account_id = smtp_account_ids[0]
        channel_id = self.charm.notifications.email_channel_id(smtp_account_id)
        group_id = self.charm.notifications.recipient_group_id(smtp_account_id)
        for config_id in (channel_id, group_id, smtp_account_id):
            try:
                self.charm.notifications.delete_config(config_id)
            except OpenSearchHttpError:
                logger.exception("Failed deleting notifications config %s", config_id)

        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:
        """Handles secret changes (support multiple smtp relations).

        Args:
            event: SecretChangedEvent
        """
        label = event.secret.label

        if not label or SMTP_SECRET_LABEL not in label:
            return

        content = event.secret.get_content(refresh=True)

        if not (match := re.search(r"(plugin-notifications-\d+)", event.secret.label)):
            return
        label = match.group(1)

        if not (plugin_config := decode_plugin_secret_content(content, label)):
            return

        if not (keys := plugin_config.get("keys")):
            return

        self.charm.plugin_manager.put_plugin_config(
            scope=Scope.UNIT,
            label=label,
            cleanup={"keys": list(keys.keys())},
        )

        self.charm.keystore_manager.put_entries(keys)
        self.charm.opensearch_keystore_events.reload_event.emit()
