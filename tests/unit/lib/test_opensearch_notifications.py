# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""The unit tests for Notifications REST client."""
from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest
import yaml
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_notifications import (
    NotificationsClientError,
    OpenSearchNotificationsManager,
    TransportSecurity,
)
from ops import testing
from ops.charm import ActionEvent, CharmBase
from ops.framework import StoredState


@dataclass
class TransportSec:
    """Helper to stub smtp-integrator TransportSecurity-like object."""

    value: str


def _http_err(code: int, text: str = "error") -> OpenSearchHttpError:
    """Create an OpenSearchHttpError with response_code."""
    return OpenSearchHttpError(response_text=text, response_code=code)


META_YAML = """
name: notifications-test-charm
description: charm for OpenSearchNotificationsManager unit tests
summary: test charm
"""

ACTIONS_YAML = """
check-transport-security:
  description: normalize transport security
  params:
    input:
      type: string

put-smtp-sender:
  description: put smtp sender
  params:
    exists:
      type: boolean
    transport_security:
      type: string

put-email-group:
  description: put email group
  params:
    recipients_json:
      type: string

put-email-channel:
  description: put email channel
  params:
    fallback_recipients_json:
      type: string

delete-config:
  description: delete a config
  params:
    config_id:
      type: string

config_exists:
  description: test _exists
  params:
    config_id:
      type: string

create-config:
  description: call _create_config

update-config:
  description: call _update_config
"""


class NotificationsManagerCharm(CharmBase):
    """A tiny charm that exposes NotificationsClient calls via actions."""

    _stored = StoredState()

    os_client: MagicMock | None = None

    def __init__(self, *args):
        super().__init__(*args)

        if self.os_client is None:
            self.os_client = MagicMock()

        self.client = OpenSearchNotificationsManager(self.os_client)

        self.framework.observe(self.on.put_smtp_sender_action, self._on_put_smtp_sender)
        self.framework.observe(self.on.put_email_group_action, self._on_put_email_group)
        self.framework.observe(self.on.put_email_channel_action, self._on_put_email_channel)
        self.framework.observe(self.on.delete_config_action, self._on_delete_config)
        self.framework.observe(self.on.config_exists_action, self._on_config_exists)
        self.framework.observe(self.on.create_config_action, self._on_create_config)
        self.framework.observe(self.on.update_config_action, self._on_update_config)

    def _on_put_smtp_sender(self, event: ActionEvent):
        exists = bool(event.params.get("exists", False))
        ts = TransportSecurity(event.params.get("transport_security", "tls"))

        self.client._exists = MagicMock(return_value=exists)

        self.client.put_smtp_sender(
            smtp_account_id="smtp-0",
            host="smtp.example.com",
            port=25,
            transport_security=ts,
            from_address="a@b.com",
        )
        event.set_results({"ok": "true"})

    def _on_put_email_group(self, event: ActionEvent):
        recipients = json.loads(event.params.get("recipients_json", "[]"))

        self.client.put_email_group(group_id="group", recipients=recipients)
        event.set_results({"ok": "true"})

    def _on_put_email_channel(self, event: ActionEvent):
        fallback = json.loads(event.params.get("fallback_recipients_json", "null"))

        self.client.config_exists = MagicMock(return_value=False)
        self.client.put_email_channel(
            channel_id="channel",
            smtp_account_id="sender",
            email_group_ids=["group1", "group2"],
            fallback_recipients=fallback,
        )

        event.set_results({"ok": "true"})

    def _on_delete_config(self, event: ActionEvent):
        config_id = event.params["config_id"]
        try:
            self.client.delete_config(config_id)
        except OpenSearchHttpError as e:
            event.fail(f"Failed to delete notifications config_id={config_id}: {e}")
            return
        event.set_results({"ok": "true"})

    def _on_config_exists(self, event: ActionEvent):
        config_id = event.params["config_id"]
        try:
            ok = self.client.config_exists(config_id)
        except OpenSearchHttpError as e:
            event.fail(f"OpenSearchHttpError code={e.response_code}")
            return
        event.set_results({"exists": "true" if ok else "false"})

    def _on_create_config(self, event: ActionEvent):
        try:
            self.client._create_config(config_id="x", name="x", config={"a": 1})
        except (NotificationsClientError, OpenSearchHttpError) as e:
            event.fail(str(e))
            return
        event.set_results({"ok": "true"})

    def _on_update_config(self, event: ActionEvent):
        try:
            self.client._update_config(config_id="x", config={"a": 1})
        except (NotificationsClientError, OpenSearchHttpError) as e:
            event.fail(str(e))
            return
        event.set_results({"ok": "true"})


@pytest.fixture
def opensearch_mock() -> MagicMock:
    """Mocked OpenSearch HTTP client used by Notifications client."""
    return MagicMock()


@pytest.fixture
def ctx(opensearch_mock: MagicMock) -> testing.Context:
    NotificationsManagerCharm.os_client = opensearch_mock

    meta = yaml.safe_load(META_YAML)
    actions = yaml.safe_load(ACTIONS_YAML)

    return testing.Context(
        charm_type=NotificationsManagerCharm,
        meta=meta,
        actions=actions,
    )


@pytest.mark.parametrize(
    "exists,transport_security,expected_method",
    [
        (False, "tls", "ssl"),
        (True, "none", "none"),
    ],
)
def test_put_smtp_sender_when_called_then_creates_or_updates_payload(
    ctx: testing.Context,
    opensearch_mock: MagicMock,
    exists: bool,
    transport_security: str,
    expected_method: str,
) -> None:
    opensearch_mock.request.reset_mock()

    ctx.run(
        ctx.on.action(
            "put-smtp-sender",
            params={"exists": exists, "transport_security": transport_security},
        ),
        testing.State(leader=True),
    )

    # _create_or_update_config: GET (exists) then POST or PUT
    assert opensearch_mock.request.call_count == 2
    method, path = opensearch_mock.request.call_args_list[1].args[:2]
    payload = opensearch_mock.request.call_args_list[1].kwargs["payload"]

    cfg = payload["config"]
    assert cfg["config_type"] == "smtp_account"
    assert cfg["smtp_account"]["method"] == expected_method

    # distinguish create vs update by path
    if exists:
        assert "smtp-0" in path


def test_smtp_account_id_from_relation() -> None:
    assert OpenSearchNotificationsManager.smtp_account_id_from_relation(0) == "smtp-0"
    assert OpenSearchNotificationsManager.smtp_account_id_from_relation(1) == "smtp-1"
    assert OpenSearchNotificationsManager.smtp_account_id_from_relation(42) == "smtp-42"


def test_get_smtp_config_uses_relation_id_for_config_id(
    opensearch_mock: MagicMock,
) -> None:
    client = OpenSearchNotificationsManager(opensearch_mock)
    params = MagicMock()
    params.smtp_sender = "no-reply@example.com"
    params.transport_security = TransportSec("starttls")

    config = client.get_smtp_config(params, relation_id=3)

    assert config.sender_email == "no-reply@example.com"
    assert config.smtp_account_id == "smtp-3"
    assert config.label == f"{client.label(3)}"
    assert config.group_id == "smtp-3_recipients"
    assert config.channel_id == "smtp-3_email-channel"
    assert config.transport_security == TransportSecurity.STARTTLS


@pytest.mark.parametrize(
    "recipients,expected_recipient_list",
    [
        (["a@x.com", "b@y.com"], [{"recipient": "a@x.com"}, {"recipient": "b@y.com"}]),
        ([], []),
    ],
)
def test_put_email_group_when_called_then_payload_shape_is_correct(
    ctx: testing.Context, opensearch_mock: MagicMock, recipients, expected_recipient_list
) -> None:
    opensearch_mock.request.reset_mock()

    ctx.run(
        ctx.on.action("put-email-group", params={"recipients_json": json.dumps(recipients)}),
        testing.State(leader=True),
    )
    assert opensearch_mock.request.call_count == 2

    # exists check
    (first_method, first_path) = opensearch_mock.request.call_args_list[0].args[:2]
    assert first_method == "GET"
    assert first_path == "/_plugins/_notifications/configs/group"

    # create/update request
    (second_method, second_path) = opensearch_mock.request.call_args_list[1].args[:2]
    assert second_method in ("POST", "PUT")

    payload = opensearch_mock.request.call_args_list[1].kwargs["payload"]
    cfg = payload["config"]
    assert cfg["config_type"] == "email_group"
    assert cfg["email_group"]["recipient_list"] == expected_recipient_list


@pytest.mark.parametrize(
    "fallback_recipients,expected_recipient_list",
    [
        (["c@z.com"], [{"recipient": "c@z.com"}]),
        (None, []),
        ([], []),
    ],
)
def test_put_email_channel_when_called_then_create_recipient_list(
    ctx: testing.Context, opensearch_mock: MagicMock, fallback_recipients, expected_recipient_list
) -> None:
    opensearch_mock.request.reset_mock()

    ctx.run(
        ctx.on.action(
            "put-email-channel",
            params={"fallback_recipients_json": json.dumps(fallback_recipients)},
        ),
        testing.State(leader=True),
    )

    # charm mocks config_exists(return_value=False), so only create (POST) is sent
    assert opensearch_mock.request.call_count == 1
    method, path = opensearch_mock.request.call_args.args[:2]
    payload = opensearch_mock.request.call_args.kwargs["payload"]

    assert method in ("POST", "PUT")
    assert path.startswith("/_plugins/_notifications/configs")

    cfg = payload["config"]
    assert cfg["config_type"] == "email"
    assert cfg["email"]["email_account_id"] == "sender"
    assert cfg["email"]["email_group_id_list"] == ["group1", "group2"]
    assert cfg["email"]["recipient_list"] == expected_recipient_list


def test_delete_config_when_delete_request_then_request_found(
    ctx: testing.Context, opensearch_mock: MagicMock
) -> None:
    ctx.run(
        ctx.on.action("delete-config", params={"config_id": "abc"}), testing.State(leader=True)
    )
    opensearch_mock.request.assert_called_once_with(
        "DELETE", "/_plugins/_notifications/configs/abc"
    )


def test_delete_config_when_raise_then_wraps_opensearch_error(
    ctx: testing.Context, opensearch_mock: MagicMock
) -> None:
    opensearch_mock.request.side_effect = _http_err(500)

    with pytest.raises(testing.ActionFailed) as e:
        ctx.run(
            ctx.on.action("delete-config", params={"config_id": "abc"}), testing.State(leader=True)
        )

    assert "failed to delete notifications config_id=abc" in str(e.value).lower()


def test_exists_when_returns_true_then_get_ok(
    ctx: testing.Context, opensearch_mock: MagicMock
) -> None:
    opensearch_mock.request.return_value = {"ok": True}
    ctx.run(ctx.on.action("config_exists", params={"config_id": "x"}), testing.State(leader=True))
    opensearch_mock.request.assert_called_once_with("GET", "/_plugins/_notifications/configs/x")


def test_exists_when_no_object_then_get_request_succeed(
    ctx: testing.Context, opensearch_mock: MagicMock
) -> None:
    """When config does not exist (404), config_exists returns False and action succeeds."""
    opensearch_mock.request.side_effect = _http_err(404)
    ctx.run(ctx.on.action("config_exists", params={"config_id": "x"}), testing.State(leader=True))
    opensearch_mock.request.assert_called_once_with("GET", "/_plugins/_notifications/configs/x")


def test_exists_when_request_fails_then_return_opensearch_error(
    ctx: testing.Context, opensearch_mock: MagicMock
) -> None:
    opensearch_mock.request.side_effect = _http_err(503)
    with pytest.raises(testing.ActionFailed) as e:
        ctx.run(
            ctx.on.action("config_exists", params={"config_id": "x"}), testing.State(leader=True)
        )
    assert "opensearchhttperror code=503" in str(e.value).lower()


@pytest.mark.parametrize("action_name", ["create-config", "update-config"])
def test_create_or_update_when_request_error_then_wraps_opensearch_errors(
    ctx: testing.Context, opensearch_mock: MagicMock, action_name: str
) -> None:
    opensearch_mock.request.side_effect = _http_err(500)

    with pytest.raises(testing.ActionFailed):
        ctx.run(ctx.on.action(action_name), testing.State(leader=True))
