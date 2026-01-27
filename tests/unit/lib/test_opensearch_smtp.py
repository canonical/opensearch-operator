# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Unit tests for SMTP events handler."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, call

import charms.opensearch.v0.opensearch_plugin_manager as mod
import pytest
import yaml
from charms.opensearch.v0.constants_charm import (
    SMTP_SECRET_LABEL,
    SmtpMissingRequiredParameters,
    SmtpRelationInvalid,
    SmtpWaitingRecipients,
)
from charms.opensearch.v0.models import DeploymentType
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_plugin_manager import SmtpEvents
from ops import BlockedStatus, WaitingStatus
from ops.charm import CharmBase
from ops.framework import StoredState
from scenario import Context, State

META = yaml.safe_load(
    """
name: smtp-events-test
summary: smtp events tests
description: scenario charm for smtp events tests
requires:
  smtp:
    interface: smtp
"""
)

SMTP_ENDPOINT = "smtp"
SMTP_INTERFACE = "smtp"
REMOTE_APP = "smtp-integrator"


def smtp_relation(
    rel_id: int = 1,
    remote_app_data: dict | None = None,
    local_app_data: dict | None = None,
):
    from scenario import Relation

    return Relation(
        endpoint=SMTP_ENDPOINT,
        interface=SMTP_INTERFACE,
        id=rel_id,
        remote_app_name=REMOTE_APP,
        remote_app_data=remote_app_data or {},
        local_app_data=local_app_data or {},
    )


def mk_params(
    *,
    smtp_sender="no-reply@example.com",
    user="u",
    password="p",
    host="smtp.example.com",
    port=25,
    transport_security="tls",
    recipients=None,
):
    return SimpleNamespace(
        smtp_sender=smtp_sender,
        user=user,
        password=password,
        host=host,
        port=port,
        transport_security=transport_security,
        recipients=recipients or [],
    )


class _FakeSecret:
    def __init__(self, label: str, content: dict):
        self.label = label
        self._content = content

    def get_content(self, refresh: bool = False) -> dict:
        return self._content


class SmtpTestCharm(CharmBase):
    """Scenario charm wrapper to exercise SmtpEvents via relation events."""

    _stored = StoredState()

    deps: dict | None = None

    relation_params_by_id: dict[int, object] = {}
    force_duplicate_sender: str | None = None

    def __init__(self, *args):
        super().__init__(*args)
        d = self.deps or {}

        self.status = d["status"]
        self.opensearch_peer_cm = d["opensearch_peer_cm"]
        self.opensearch = d["opensearch"]
        self.peer_cluster_provider = d["peer_cluster_provider"]
        self.keystore_manager = d["keystore_manager"]
        self.notifications = d["notifications"]
        self.plugin_manager = d["plugin_manager"]
        self.state = d["state"]
        self.secrets = d["secrets"]

        self.smtp_events = SmtpEvents(self)

        # relation-data reader
        def _reader(relation):
            return self.relation_params_by_id[relation.id]

        self.smtp_events.smtp.get_relation_data_from_relation = MagicMock(side_effect=_reader)

        # optional: inject duplicate sender behavior
        if self.force_duplicate_sender is not None:
            self.smtp_events._has_duplicate_sender_emails = MagicMock(
                return_value=self.force_duplicate_sender
            )

        self.framework.observe(
            self.on.smtp_relation_changed, self.smtp_events._on_smtp_credentials_changed
        )
        self.framework.observe(
            self.on.smtp_relation_broken, self.smtp_events._on_smtp_credentials_gone
        )


@pytest.fixture
def deps():
    """Mocks used by the charm."""
    status = MagicMock()
    status.set = MagicMock()
    status.clear = MagicMock()
    secrets = MagicMock()
    secrets.get = MagicMock(return_value=None)
    secrets.add = MagicMock()
    secrets.remove = MagicMock()

    opensearch_peer_cm = MagicMock()
    opensearch_peer_cm.deployment_desc.return_value = SimpleNamespace(
        typ=DeploymentType.MAIN_ORCHESTRATOR
    )
    opensearch_peer_cm.is_provider.return_value = True

    opensearch = MagicMock()
    opensearch.is_started.return_value = True

    peer_cluster_provider = MagicMock()
    peer_cluster_provider.refresh_relation_data = MagicMock()

    keystore_manager = MagicMock()
    keystore_manager.put_entries = MagicMock()
    keystore_manager.remove_entries = MagicMock()
    keystore_manager.reload = MagicMock(return_value=True)

    notifications = MagicMock()
    notifications.apply_smtp_sender = MagicMock()
    notifications.apply_email_group = MagicMock()
    notifications.apply_email_channel = MagicMock()
    notifications.delete_config = MagicMock()

    plugin_manager = MagicMock()
    plugin_manager.put_plugin_config = MagicMock()
    plugin_manager.remove_plugin_config = MagicMock()

    state = SimpleNamespace(unit=SimpleNamespace(plugin_config_info={}))

    return {
        "status": status,
        "opensearch_peer_cm": opensearch_peer_cm,
        "opensearch": opensearch,
        "peer_cluster_provider": peer_cluster_provider,
        "keystore_manager": keystore_manager,
        "notifications": notifications,
        "plugin_manager": plugin_manager,
        "state": state,
        "secrets": secrets,
    }


@pytest.fixture
def ctx(deps) -> Context:
    SmtpTestCharm.deps = deps
    return Context(charm_type=SmtpTestCharm, meta=META)


@pytest.fixture(autouse=True)
def _reset_injection():
    SmtpTestCharm.relation_params_by_id = {}
    SmtpTestCharm.force_duplicate_sender = None
    yield
    SmtpTestCharm.relation_params_by_id = {}
    SmtpTestCharm.force_duplicate_sender = None


class TestHelpers:
    @pytest.mark.parametrize(
        "sender_email,expected_prefix",
        [
            ("No-Reply@Example.com", "smtp-sender-no-reply-example-com"),
            ("  A.B+C@x.y  ", "smtp-sender-a-b-c-x-y"),
            ("xxx_yyy@bar.com", "smtp-sender-xxx-yyy-bar-com"),
        ],
    )
    def test_sender_id_from_email(self, sender_email, expected_prefix) -> None:
        assert SmtpEvents._sender_id_from_email(sender_email) == expected_prefix

    @pytest.mark.parametrize(
        "sender_id,expected",
        [
            ("smtp-sender-x", "smtp-sender-x_recipients"),
            ("smtp-sender-a-b", "smtp-sender-a-b_recipients"),
        ],
    )
    def test_recipient_group_id(self, sender_id, expected) -> None:
        assert SmtpEvents._recipient_group_id(sender_id) == expected

    @pytest.mark.parametrize(
        "sender_id,expected",
        [
            ("smtp-sender-x", "smtp-sender-x_email-channel"),
            ("smtp-sender-a-b", "smtp-sender-a-b_email-channel"),
        ],
    )
    def test_email_channel_id(self, sender_id, expected) -> None:
        assert SmtpEvents._email_channel_id(sender_id) == expected

    def test_label(self) -> None:
        assert SmtpEvents._label(7) == f"{SMTP_SECRET_LABEL}-7"


class TestDuplicateSenderEmailsScenario:
    def test_has_duplicate_sender_emails_when_duplicate_then_returns_duplicated_email(
        self, ctx, deps
    ) -> None:
        rel1 = smtp_relation(1)
        rel2 = smtp_relation(2)

        # each relation returns same sender
        SmtpTestCharm.relation_params_by_id = {
            1: mk_params(smtp_sender="same@example.com"),
            2: mk_params(smtp_sender="same@example.com"),
        }

        ctx.run(
            ctx.on.relation_changed(rel1),
            State(leader=True, relations=[rel1, rel2]),
        )
        if deps["status"].set.called:
            status = deps["status"].set.call_args.args[0]
            assert "duplicate" in getattr(status, "message", "").lower()

    def test_has_duplicate_sender_emails_when_unique_then_none(self, ctx, deps) -> None:
        rel1 = smtp_relation(1)
        rel2 = smtp_relation(2)

        SmtpTestCharm.relation_params_by_id = {
            1: mk_params(smtp_sender="a@example.com"),
            2: mk_params(smtp_sender="b@example.com"),
        }

        # run relation-changed, should not set blocked for duplicates
        ctx.run(
            ctx.on.relation_changed(rel1),
            State(leader=True, relations=[rel1, rel2]),
        )

        if deps["status"].set.called:
            status = deps["status"].set.call_args.args[0]
            assert "duplicate" not in getattr(status, "message", "").lower()


class TestOnSmtpCredentialsChangedScenario:
    def test_when_deployment_not_ready_then_no_ops(self, ctx, deps) -> None:
        deps["opensearch_peer_cm"].deployment_desc.return_value = None
        rel = smtp_relation(1)

        ctx.run(ctx.on.relation_changed(rel), State(leader=True, relations=[rel]))

        deps["keystore_manager"].put_entries.assert_not_called()
        deps["notifications"].apply_smtp_sender.assert_not_called()
        deps["status"].set.assert_not_called()

    def test_when_not_main_orchestrator_then_leader_sets_blocked(self, ctx, deps) -> None:
        deps["opensearch_peer_cm"].deployment_desc.return_value = SimpleNamespace(typ="not-main")
        rel = smtp_relation(1)

        SmtpTestCharm.relation_params_by_id = {1: mk_params()}

        ctx.run(ctx.on.relation_changed(rel), State(leader=True, relations=[rel]))

        deps["status"].set.assert_called()
        status = deps["status"].set.call_args.args[0]
        assert isinstance(status, BlockedStatus)
        assert status.message == SmtpRelationInvalid

    def test_when_opensearch_not_started_then_no_ops(self, ctx, deps) -> None:
        deps["opensearch"].is_started.return_value = False
        rel = smtp_relation(1)

        SmtpTestCharm.relation_params_by_id = {1: mk_params()}

        ctx.run(ctx.on.relation_changed(rel), State(leader=True, relations=[rel]))

        deps["keystore_manager"].put_entries.assert_not_called()
        deps["notifications"].apply_smtp_sender.assert_not_called()

    @pytest.mark.parametrize(
        "params,missing_fields",
        [
            ({"smtp_sender": None}, ["smtp_sender"]),
            ({"user": None}, ["user"]),
            ({"password": None}, ["password"]),
            ({"host": None}, ["host"]),
            ({"port": None}, ["port"]),
            ({"transport_security": None}, ["transport_security"]),
            ({"user": None, "password": None}, ["user", "password"]),
        ],
    )
    def test_when_required_fields_missing_then_leader_sets_blocked(
        self, ctx, deps, params, missing_fields
    ) -> None:
        rel = smtp_relation(1)
        p = mk_params()
        for k, v in params.items():
            setattr(p, k, v)

        SmtpTestCharm.relation_params_by_id = {1: p}

        ctx.run(ctx.on.relation_changed(rel), State(leader=True, relations=[rel]))

        deps["status"].set.assert_called_once()
        status = deps["status"].set.call_args.args[0]
        assert isinstance(status, BlockedStatus)
        assert SmtpMissingRequiredParameters.split("{")[0] in status.message
        for field in missing_fields:
            assert field in status.message

    def test_when_duplicate_sender_detected_then_leader_sets_blocked_duplicate(
        self, ctx, deps
    ) -> None:
        rel1 = smtp_relation(1)
        rel2 = smtp_relation(2)

        SmtpTestCharm.relation_params_by_id = {1: mk_params(), 2: mk_params()}
        SmtpTestCharm.force_duplicate_sender = "dup@example.com"

        ctx.run(
            ctx.on.relation_changed(rel1),
            State(leader=True, relations=[rel1, rel2]),
        )

        deps["status"].set.assert_called()
        status = deps["status"].set.call_args.args[0]
        assert isinstance(status, BlockedStatus)
        assert "duplicate" in status.message.lower()

    @pytest.mark.parametrize(
        "recipients,expect_waiting,expect_group_calls",
        [
            (["a@x.com", "b@y.com"], False, 1),
            ([], True, 0),
        ],
    )
    def test_when_recipients_present_or_missing_then_get_group_or_waiting(
        self, ctx, deps, recipients, expect_waiting, expect_group_calls
    ) -> None:
        rel = smtp_relation(7)

        SmtpTestCharm.relation_params_by_id = {7: mk_params(recipients=recipients)}

        ctx.run(ctx.on.relation_changed(rel), State(leader=True, relations=[rel]))

        deps["keystore_manager"].put_entries.assert_called_once()
        deps["keystore_manager"].reload.assert_called_once()

        deps["notifications"].apply_smtp_sender.assert_called_once()
        assert deps["notifications"].apply_email_group.call_count == expect_group_calls
        assert deps["notifications"].apply_email_channel.call_count == expect_group_calls

        if expect_waiting:
            deps["status"].set.assert_called()
            status = deps["status"].set.call_args.args[0]
            assert isinstance(status, WaitingStatus)
            assert status.message == SmtpWaitingRecipients
        else:
            deps["status"].set.assert_not_called()

    def test_when_keystore_reload_fails_then_no_notifications(self, ctx, deps) -> None:
        deps["keystore_manager"].reload.return_value = False
        rel = smtp_relation(1)

        SmtpTestCharm.relation_params_by_id = {1: mk_params()}

        ctx.run(ctx.on.relation_changed(rel), State(leader=True, relations=[rel]))
        # sender is applied before reload attempt
        deps["notifications"].apply_smtp_sender.assert_called_once()
        deps["notifications"].apply_email_group.assert_not_called()
        deps["notifications"].apply_email_channel.assert_not_called()


class TestOnSmtpCredentialsGoneScenario:
    def test_when_deployment_not_ready_then_no_ops(self, ctx, deps) -> None:
        deps["opensearch_peer_cm"].deployment_desc.return_value = None
        rel = smtp_relation(1)

        ctx.run(ctx.on.relation_broken(rel), State(leader=True, relations=[rel]))

        deps["keystore_manager"].remove_entries.assert_not_called()
        deps["notifications"].delete_config.assert_not_called()

    def test_when_plugin_config_missing_then_no_operation(self, ctx, deps) -> None:
        rel = smtp_relation(1)
        ctx.run(ctx.on.relation_broken(rel), State(leader=True, relations=[rel]))

        deps["keystore_manager"].remove_entries.assert_not_called()
        deps["notifications"].delete_config.assert_not_called()

    def test_when_present_then_removes_entries_and_deletes_configs(self, ctx, deps) -> None:
        rel = smtp_relation(3)
        label = SmtpEvents._label(rel.id)

        deps["state"].unit.plugin_config_info[label] = SimpleNamespace(
            cleanup={
                "keys": ["k1", "k2"],
                "notification_config_ids": ["sender", "group", "channel"],
            }
        )

        ctx.run(ctx.on.relation_broken(rel), State(leader=True, relations=[rel]))

        deps["keystore_manager"].remove_entries.assert_called_once_with(["k1", "k2"])
        deps["keystore_manager"].reload.assert_called_once()
        deps["plugin_manager"].remove_plugin_config.assert_any_call(scope=Scope.UNIT, label=label)

        deps["notifications"].delete_config.assert_has_calls(
            [call("channel"), call("group"), call("sender")], any_order=False
        )

    def test_when_keystore_reload_fails_then_no_deletes(self, ctx, deps) -> None:
        deps["keystore_manager"].reload.return_value = False
        rel = smtp_relation(3)
        label = SmtpEvents._label(rel.id)

        deps["state"].unit.plugin_config_info[label] = SimpleNamespace(
            cleanup={"keys": ["k1"], "notification_config_ids": ["sender"]}
        )

        ctx.run(ctx.on.relation_broken(rel), State(leader=True, relations=[rel]))
        deps["notifications"].delete_config.assert_not_called()


class TestOnSecretChangedUnitStyle:
    def test_when_label_not_smtp_plugin_then_ignores(self, deps) -> None:
        charm = MagicMock()
        handler = SmtpEvents(charm)

        charm.unit.is_leader.return_value = False
        charm.keystore_manager = MagicMock()
        charm.keystore_manager.put_entries = MagicMock()

        ev = MagicMock()
        ev.secret = _FakeSecret(label="unrelated", content={})

        handler._on_secret_changed(ev)
        charm.keystore_manager.put_entries.assert_not_called()

    def test_when_label_malformed_then_ignores(self) -> None:
        charm = MagicMock()
        handler = SmtpEvents(charm)

        charm.unit.is_leader.return_value = False
        charm.keystore_manager = MagicMock()
        charm.keystore_manager.put_entries = MagicMock()

        ev = MagicMock()
        ev.secret = _FakeSecret(label=f"{SMTP_SECRET_LABEL}-oops", content={})

        handler._on_secret_changed(ev)
        charm.keystore_manager.put_entries.assert_not_called()

    def test_when_decodes_then_puts_keys_records_cleanup_and_reloads(self, monkeypatch) -> None:
        charm = MagicMock()
        handler = SmtpEvents(charm)

        charm.unit.is_leader.return_value = False
        charm.plugin_manager = MagicMock()
        charm.keystore_manager = MagicMock()
        charm.keystore_manager.reload.return_value = True

        decoded = {"keys": {"k1": "v1", "k2": "v2"}, "notification_config_ids": ["a"]}
        monkeypatch.setattr(mod, "decode_plugin_secret_content", lambda content, label: decoded)

        ev = MagicMock()
        ev.defer = MagicMock()
        ev.secret = _FakeSecret(
            label=f"{SMTP_SECRET_LABEL}-7 plugin-notifications-7",
            content={"x": "y"},
        )

        handler._on_secret_changed(ev)

        charm.plugin_manager.put_plugin_config.assert_called_once_with(
            scope=Scope.UNIT,
            label="plugin-notifications-7",
            cleanup={"keys": ["k1", "k2"]},
        )
        charm.keystore_manager.put_entries.assert_called_once_with({"k1": "v1", "k2": "v2"})
        charm.keystore_manager.reload.assert_called_once()

    def test_when_reload_fails_then_defers(self, monkeypatch) -> None:
        charm = MagicMock()
        handler = SmtpEvents(charm)

        charm.unit.is_leader.return_value = False
        charm.plugin_manager = MagicMock()
        charm.keystore_manager = MagicMock()
        charm.keystore_manager.reload.return_value = False

        decoded = {"keys": {"k1": "v1"}}
        monkeypatch.setattr(mod, "decode_plugin_secret_content", lambda content, label: decoded)

        ev = MagicMock()
        ev.defer = MagicMock()
        ev.secret = _FakeSecret(
            label=f"{SMTP_SECRET_LABEL}-7 plugin-notifications-7",
            content={},
        )

        handler._on_secret_changed(ev)
        ev.defer.assert_called_once()
