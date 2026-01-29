# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Notifications plugin API client (configs CRUD).

This client wraps OpenSearchDistribution.request() to manage notifications configs:
- smtp sender (config_type: smtp_account)
- email group (config_type: email_group)
- email channel (config_type: email)
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from charms.opensearch.v0.constants_charm import SMTP_SECRET_LABEL
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.smtp_integrator.v0.smtp import SmtpRelationData
from tenacity import retry, stop_after_attempt, wait_fixed


class NotificationsClientError(RuntimeError):
    """Raises when Notifications API operations fail."""


class TransportSecurity(str, Enum):
    """SMTP transport security protocol."""

    NONE = "none"
    STARTTLS = "starttls"
    TLS = "tls"

    def api_method(self) -> str:
        """Return the OpenSearch Notifications API method string."""
        return {"none": "none", "starttls": "start_tls", "tls": "ssl"}[self.value]


@dataclass(frozen=True)
class NotificationsConfigRef:
    """Notifications config referencing CRUD operations.

    Args:
        config_id: the id of the notification config
        name: the name of the notification config
    """

    config_id: str
    name: str


@dataclass(frozen=True)
class SmtpConfig:
    """SMTP-related config derived from relation data."""

    sender_email: str
    smtp_account_id: str
    label: str
    group_id: str
    channel_id: str
    transport_security: TransportSecurity


class OpenSearchNotificationsManager:
    """Notifications plugin API client using OpenSearchDistribution request."""

    def __init__(self, opensearch: OpenSearchDistribution):
        """The constructor for OpenSearchNotificationsManager.

        Args:
            opensearch: an OpenSearchDistribution instance
        """
        self.opensearch = opensearch

    @staticmethod
    def label(relation_id: int) -> str:
        """Return label for this relation.

        Args:
            relation_id: relation id

        Returns:
            relation label
        """
        return f"{SMTP_SECRET_LABEL}-{relation_id}"

    @staticmethod
    def recipient_group_id(smtp_account_id: str) -> str:
        """Return recipient group id for this relation.

        Args:
            smtp_account_id: smtp account config id

        Returns:
            recipient group id
        """
        return f"{smtp_account_id}_recipients"

    @staticmethod
    def email_channel_id(smtp_account_id: str) -> str:
        """Return email channel id for this relation.

        Args:
            smtp_account_id: smtp account config id

        Returns:
            email channel id
        """
        return f"{smtp_account_id}_email-channel"

    @staticmethod
    def smtp_account_id_from_email(sender_email: str) -> str:
        """Return smtp account config id for this relation.

        Args:
            sender_email: sender email

        Returns:
            smtp account config id
        """
        s = sender_email.strip().lower()
        s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
        return f"smtp-sender-{s}"

    def get_smtp_config(self, parameters: SmtpRelationData, relation_id: int) -> SmtpConfig:
        """Derive SMTP-related config IDs and normalized values from relation data.

        Args:
            parameters: SMTP relation data from the smtp-integrator.
            relation_id: ID of the relation.

        Returns:
            SmtpConfig with sender_email, smtp_account_id, label, group_id,
            channel_id, and transport_security.
        """
        sender_email = str(parameters.smtp_sender)
        smtp_account_id = self.smtp_account_id_from_email(sender_email)
        label = self.label(relation_id)
        group_id = self.recipient_group_id(smtp_account_id)
        channel_id = self.email_channel_id(smtp_account_id)
        ts = parameters.transport_security
        raw_ts = ts.value if hasattr(ts, "value") else ts
        transport_security = TransportSecurity(str(raw_ts).strip().lower())
        return SmtpConfig(
            sender_email=sender_email,
            smtp_account_id=smtp_account_id,
            label=label,
            group_id=group_id,
            channel_id=channel_id,
            transport_security=transport_security,
        )

    def put_smtp_sender(
        self,
        *,
        smtp_account_id: str,
        host: str,
        port: int,
        transport_security: TransportSecurity,
        from_address: str,
        description: str = "",
    ) -> None:
        """Put smtp account configuration.

        Args:
            smtp_account_id: the id of the smtp account config
            host: the smtp host
            port: the smtp port
            transport_security: security protocol to use for the outgoing SMTP relay
            from_address: the smtp address
            description: the smtp description
        """
        method = transport_security.api_method()
        config = {
            "name": smtp_account_id,
            "description": description or f"SMTP sender: ({smtp_account_id})",
            "config_type": "smtp_account",
            "smtp_account": {
                "host": host,
                "port": int(port),
                "method": method,
                "from_address": from_address,
            },
        }
        self._create_or_update_config(
            config_id=smtp_account_id, name=smtp_account_id, config=config
        )

    def put_email_group(
        self,
        *,
        group_id: str,
        recipients: Iterable[str],
        description: str = "",
    ) -> None:
        """Put email group configuration.

        Args:
            group_id: the id of the email group
            recipients: the email recipients
            description: the email description
        """
        config = {
            "name": group_id,
            "description": description or f"Email group managed by ({group_id})",
            "config_type": "email_group",
            "email_group": {
                "recipient_list": [{"recipient": r} for r in recipients],
            },
        }
        self._create_or_update_config(config_id=group_id, name=group_id, config=config)

    def put_email_channel(
        self,
        *,
        channel_id: str,
        smtp_account_id: str,
        email_group_ids: list[str],
        fallback_recipients: Iterable[str] | None = None,
        description: str = "",
    ) -> None:
        """Put email channel configuration.

        Args:
            channel_id: the id of the email channel
            smtp_account_id: the id of the smtp account config (email_account_id in API)
            email_group_ids: the email group ids
            fallback_recipients: the email recipients
            description: the email description
        """
        config = {
            "name": channel_id,
            "description": description or f"Email channel: ({channel_id})",
            "config_type": "email",
            "email": {
                "email_account_id": smtp_account_id,
                "recipient_list": [{"recipient": r} for r in (fallback_recipients or [])],
                "email_group_id_list": list(email_group_ids),
            },
        }
        self._create_or_update_config(config_id=channel_id, name=channel_id, config=config)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def delete_config(self, config_id: str) -> None:
        """Delete config by id.

        404 (config already gone) is treated as success.

        Args:
            config_id: Notification Config ID
        """
        try:
            self.opensearch.request("DELETE", f"/_plugins/_notifications/configs/{config_id}")
        except OpenSearchHttpError as exc:
            code = getattr(exc, "response_code", None)
            if code == 404:
                return
            raise

    def _create_or_update_config(
        self, *, config_id: str, name: str, config: dict[str, object]
    ) -> None:
        """Create config if missing, otherwise update.

        Args:
            config_id: Notification Config ID
            name: Notification Name
            config: Notification Config
        """
        try:
            if self.config_exists(config_id):
                self._update_config(config_id=config_id, config=config)
            else:
                self._create_config(config_id=config_id, name=name, config=config)
        except OpenSearchHttpError as exc:
            raise NotificationsClientError(
                f"Failed notifications config_id={config_id}: {exc}"
            ) from exc

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def config_exists(self, config_id: str) -> bool:
        """Check if config exists.

        Args:
            config_id: Notification Config ID

        Returns:
            True if config exists, False if 404.
        """
        try:
            self.opensearch.request("GET", f"/_plugins/_notifications/configs/{config_id}")
            return True
        except OpenSearchHttpError as exc:
            code = getattr(exc, "response_code", None)
            if code == 404:
                return False
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def _create_config(self, *, config_id: str, name: str, config: dict[str, object]) -> None:
        """Create notification config.

        Args:
            config_id: Notification Config ID
            name: Notification Name
            config: Notification Config
        """
        payload = {"config_id": config_id, "name": name, "config": config}
        self.opensearch.request("POST", "/_plugins/_notifications/configs/", payload=payload)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3), reraise=True)
    def _update_config(self, *, config_id: str, config: dict[str, object]) -> None:
        """Update notification config.

        Args:
            config_id: Notification Config ID
            config: Notification Config
        """
        payload = {"config": config}
        self.opensearch.request(
            "PUT", f"/_plugins/_notifications/configs/{config_id}", payload=payload
        )
