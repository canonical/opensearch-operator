# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch Notifications plugin API client (configs CRUD).

This client wraps OpenSearchDistribution.request() to manage notifications configs:
- smtp sender (config_type: smtp_account)
- email group (config_type: email_group)
- email channel (config_type: email)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Union

from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError


class NotificationsClientError(RuntimeError):
    """Raised when Notifications API operations fail."""


@dataclass(frozen=True)
class NotificationsConfigRef:
    """Notifications config referencing CRUD operations.

    Args:
        config_id: the id of the notification config
        name: the name of the notification config
    """

    config_id: str
    name: str


def check_transport_security(transport_security) -> str:
    """Check if transport_security is valid.

    Args:
        transport_security: an OpenSearchDistribution instance

    Returns:
        tls or none

    Raises:
        ValueError
    """
    val = getattr(transport_security, "value", transport_security)
    val = str(val).strip().lower()

    if val == "none":
        return "none"
    if val == "tls":
        return "tls"

    raise ValueError(f"Unsupported transport_security: {val}")


class OpenSearchNotificationsClient:
    """Notifications plugin API client using OpenSearchDistribution.request()."""

    def __init__(self, opensearch):
        """The constructor for OpenSearchNotificationsClient.

        Args:
            opensearch: an OpenSearchDistribution instance
        """
        self.opensearch = opensearch

    def apply_smtp_sender(
        self,
        *,
        sender_id: str,
        host: str,
        port: int,
        transport_security: Union[str, Any],
        from_address: str,
        description: str = "",
        is_enabled: bool = True,
    ) -> NotificationsConfigRef:
        """Apply smtp sender configuration.

        Args:
            sender_id: the id of the sender
            host: the smtp host
            port: the smtp port
            transport_security: an OpenSearchDistribution instance
            from_address: the smtp address
            description: the smtp description
            is_enabled: whether the smtp sender is enabled

        Returns:
            NotificationsConfigRef: the notification config
        """
        method = check_transport_security(transport_security)
        config = {
            "name": sender_id,
            "description": description or f"SMTP sender: ({sender_id})",
            "config_type": "smtp_account",
            "is_enabled": is_enabled,
            "smtp_account": {
                "host": host,
                "port": int(port),
                "method": method,
                "from_address": from_address,
            },
        }
        self._create_or_update_config(config_id=sender_id, name=sender_id, config=config)
        return NotificationsConfigRef(config_id=sender_id, name=sender_id)

    def apply_email_group(
        self,
        *,
        group_id: str,
        recipients: Iterable[str],
        description: str = "",
        is_enabled: bool = True,
    ) -> NotificationsConfigRef:
        """Apply email group configuration.

        Args:
            group_id: the id of the email group
            recipients: the email recipients
            description: the email description
            is_enabled: whether the email group is enabled

        Returns:
            NotificationsConfigRef: the notification config
        """
        config = {
            "name": group_id,
            "description": description or f"Email group managed by ({group_id})",
            "config_type": "email_group",
            "is_enabled": is_enabled,
            "email_group": {
                "recipient_list": [{"recipient": r} for r in recipients],
            },
        }
        self._create_or_update_config(config_id=group_id, name=group_id, config=config)
        return NotificationsConfigRef(config_id=group_id, name=group_id)

    def apply_email_channel(
        self,
        *,
        channel_id: str,
        sender_id: str,
        email_group_ids: List[str],
        fallback_recipients: Optional[Iterable[str]] = None,
        description: str = "",
        is_enabled: bool = True,
    ) -> NotificationsConfigRef:
        """Apply email channel configuration.

        Args:
            channel_id: the id of the email channel
            sender_id: the id of the email sender
            email_group_ids: the email group ids
            fallback_recipients: the email recipients
            description: the email description
            is_enabled: whether the email channel is enabled

        Returns:
            NotificationsConfigRef: the notification config
        """
        config = {
            "name": channel_id,
            "description": description or f"Email channel: ({channel_id})",
            "config_type": "email",
            "is_enabled": is_enabled,
            "email": {
                "email_account_id": sender_id,
                "recipient_list": [{"recipient": r} for r in (fallback_recipients or [])],
                "email_group_id_list": list(email_group_ids),
            },
        }
        self._create_or_update_config(config_id=channel_id, name=channel_id, config=config)
        return NotificationsConfigRef(config_id=channel_id, name=channel_id)

    def delete_config(self, config_id: str) -> None:
        """Delete config by id.

        Args:
            config_id: Notification Config ID
        """
        try:
            self.opensearch.request("DELETE", f"/_plugins/_notifications/configs/{config_id}")
        except OpenSearchHttpError as exc:
            raise NotificationsClientError(
                f"Failed to delete notifications config_id={config_id}: {exc}"
            ) from exc

    def _create_or_update_config(
        self, *, config_id: str, name: str, config: Dict[str, Any]
    ) -> None:
        """Create if missing, otherwise update.

        Args:
            config_id: Notification Config ID
            name: Notification Name
            config: Notification Config
        """
        if self._exists(config_id):
            self._update_config(config_id=config_id, config=config)
        else:
            self._create_config(config_id=config_id, name=name, config=config)

    def _exists(self, config_id: str) -> bool:
        """Return True if config exists, False if 404 otherwise raise.

        Args:
            config_id: Notification Config ID
        """
        try:
            self.opensearch.request("GET", f"/_plugins/_notifications/configs/{config_id}")
            return True
        except OpenSearchHttpError as exc:
            code = getattr(exc, "response_code", None)
            if code in (404, 400):
                return False
            raise

    def _create_config(self, *, config_id: str, name: str, config: Dict[str, Any]) -> None:
        """Create if missing, otherwise update.

        Args:
            config_id: Notification Config ID
            name: Notification Name
            config: Notification Config
        """
        payload = {"config_id": config_id, "name": name, "config": config}
        try:
            self.opensearch.request("POST", "/_plugins/_notifications/configs/", payload=payload)
        except OpenSearchHttpError as exc:
            raise NotificationsClientError(
                f"Failed to create notifications config_id={config_id}: {exc}"
            ) from exc

    def _update_config(self, *, config_id: str, config: Dict[str, Any]) -> None:
        """Update if missing, otherwise update.

        Args:
            config_id: Notification Config ID
            config: Notification Config
        """
        payload = {"config": config}
        try:
            self.opensearch.request(
                "PUT", f"/_plugins/_notifications/configs/{config_id}", payload=payload
            )
        except OpenSearchHttpError as exc:
            raise NotificationsClientError(
                f"Failed to update notifications config_id={config_id}: {exc}"
            ) from exc
