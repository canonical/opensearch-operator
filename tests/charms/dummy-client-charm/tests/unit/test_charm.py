# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import base64

import pytest
from machines.src.charm import DummyClientCharmCharm
from ops import testing
from scenario.errors import UncaughtCharmError

from models import GenerateBulkTrainingDataActionParams, RequestActionParams

CONSTRUCTED_CLIENT = None

CONFIG = {
    "options": {
        "opensearch-client-options": {
            "type": "string",
            "default": "{}",
        },
        "ca-cert": {
            "type": "string",
            "default": "",
        },
        "log-level": {
            "type": "string",
            "default": "info",
        },
    },
}

ACTIONS = {
    "create-dummy-docs": {
        "description": "Create dummy documents in the dummy OpenSearch indexes.",
        "params": {
            "count": {"type": "integer", "default": 5},
            "host": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "ca-cert": {"type": "string"},
        },
    },
    "generate-bulk-training-data": {
        "description": "Generate deterministic NDJSON documents for KNN training.",
        "params": {
            "index-name": {"type": "string"},
            "vector-name": {"type": "string"},
            "docs-count": {"type": "integer", "default": 100},
            "dimensions": {"type": "integer", "default": 4},
            "has-result": {"type": "boolean", "default": False},
            "host": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "ca-cert": {"type": "string"},
        },
        "required": ["index-name", "vector-name"],
    },
    "request": {
        "description": "Run a generic OpenSearch request.",
        "params": {
            "method": {"type": "string"},
            "route": {"type": "string"},
            "body": {"type": "string", "default": ""},
            "host": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "ca-cert": {"type": "string"},
            "headers": {"type": "string", "default": ""},
            "verify": {"type": "boolean", "default": True},
            "timeout": {"type": "integer", "default": 30},
        },
        "required": ["method", "route"],
    },
    "bulk-insert": {
        "description": "Run an OpenSearch bulk insert and return a compact summary.",
        "params": {
            "index-names": {"type": "string"},
            "docs-count": {"type": "integer", "default": 100},
            "blob-size": {"type": "integer", "default": 100},
            "route": {"type": "string", "default": "/_bulk"},
            "host": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "ca-cert": {"type": "string"},
            "verify": {"type": "boolean", "default": True},
            "timeout": {"type": "integer", "default": 30},
        },
        "required": ["index-names"],
    },
}


class ClientFactoryCharm(DummyClientCharmCharm):
    """Charm subclass that exposes the client factory through an event."""

    constructed_client = None

    def __init__(self, framework):
        super().__init__(framework)
        framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_config_changed(self, event):
        global CONSTRUCTED_CLIENT
        super()._on_config_changed(event)
        CONSTRUCTED_CLIENT = self._opensearch_client()


def test_start():
    """Test that the charm has the correct state after handling the start event."""
    # Arrange:
    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS)
    # Act:
    state_out = ctx.run(ctx.on.start(), testing.State())
    # Assert:
    assert state_out.workload_version == ""
    assert state_out.unit_status == testing.ActiveStatus()


def run_client_factory(config: dict[str, str | int | float | bool] | None = None):
    """Run the test charm event that builds the OpenSearch client."""
    global CONSTRUCTED_CLIENT
    CONSTRUCTED_CLIENT = None
    ctx = testing.Context(ClientFactoryCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(ctx.on.config_changed(), testing.State(config=config or {}))
    return CONSTRUCTED_CLIENT


def test_opensearch_client_uses_default_options(monkeypatch: pytest.MonkeyPatch):
    """Default config builds OpenSearchClient with no keyword options."""
    calls = []
    client = object()

    def fake_opensearch_client(**options):
        calls.append(options)
        return client

    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", fake_opensearch_client)

    assert run_client_factory() is client
    assert calls == [{}]


def test_opensearch_client_uses_json_config(monkeypatch: pytest.MonkeyPatch):
    """JSON config is parsed and passed to OpenSearchClient as keyword options."""
    calls = []
    client = object()

    def fake_opensearch_client(**options):
        calls.append(options)
        return client

    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", fake_opensearch_client)

    assert (
        run_client_factory(
            {
                "opensearch-client-options": (
                    '{"host": {"host": "10.1.2.3", "port": 9200}, '
                    '"username": "admin", '
                    '"password": "secret", '
                    '"timeout": 30}'
                )
            }
        )
        is client
    )
    assert calls == [
        {
            "host": {"host": "10.1.2.3", "port": 9200},
            "username": "admin",
            "password": "secret",
            "timeout": 30,
        }
    ]


def test_opensearch_client_writes_ca_cert_config(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """CA cert config is decoded to the fixed requests verify path."""
    calls = []
    client = object()
    ca_cert_path = tmp_path / "ca_cert.pem"
    ca_cert = "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n"

    def fake_opensearch_client(**options):
        calls.append(options)
        return client

    monkeypatch.setattr("charm.CA_CERTS_PATH", str(ca_cert_path))
    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", fake_opensearch_client)

    assert (
        run_client_factory(
            {
                "opensearch-client-options": '{"host": {"host": "10.1.2.3", "port": 9200}}',
                "ca-cert": base64.b64encode(ca_cert.encode()).decode(),
            }
        )
        is client
    )
    assert ca_cert_path.read_text() == ca_cert
    assert calls == [
        {
            "host": {"host": "10.1.2.3", "port": 9200},
        }
    ]


def test_opensearch_client_rejects_invalid_ca_cert_config():
    """CA cert config must be valid base64."""
    with pytest.raises(
        UncaughtCharmError,
        match="ca-cert must be a valid base64-encoded string",
    ):
        run_client_factory({"ca-cert": "not base64"})


def test_config_changed_updates_ca_cert_file(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """Config changed writes the configured CA cert without building a client."""
    ca_cert_path = tmp_path / "ca_cert.pem"
    ca_cert = "-----BEGIN CERTIFICATE-----\nchanged-cert\n-----END CERTIFICATE-----\n"

    monkeypatch.setattr("charm.CA_CERTS_PATH", str(ca_cert_path))

    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(
        ctx.on.config_changed(),
        testing.State(
            config={
                "ca-cert": base64.b64encode(ca_cert.encode()).decode(),
            }
        ),
    )

    assert ca_cert_path.read_text() == ca_cert


def test_opensearch_client_rejects_invalid_json():
    """Invalid JSON raises a clear config error."""
    with pytest.raises(
        UncaughtCharmError,
        match="opensearch-client-options must be valid JSON",
    ):
        run_client_factory({"opensearch-client-options": "{not-json"})


def test_opensearch_client_rejects_non_object_json():
    """JSON config must be an object so it can be used as keyword options."""
    with pytest.raises(
        UncaughtCharmError,
        match="opensearch-client-options must be a JSON object",
    ):
        run_client_factory({"opensearch-client-options": "[]"})


def test_opensearch_client_rejects_use_ssl_config():
    """SSL is always enabled and is not configurable."""
    with pytest.raises(UncaughtCharmError, match="Extra inputs are not permitted"):
        run_client_factory({"opensearch-client-options": '{"host": "10.1.2.3", "use_ssl": false}'})


@pytest.mark.parametrize("option", ["verify_certs", "ca_certs"])
def test_opensearch_client_rejects_verify_config(option: str):
    """Requests verify is always CA_CERTS_PATH and is not configurable."""
    value = '"/path/to/ca.pem"' if option == "ca_certs" else "false"

    with pytest.raises(UncaughtCharmError, match="Extra inputs are not permitted"):
        run_client_factory(
            {"opensearch-client-options": f'{{"host": "10.1.2.3", "{option}": {value}}}'}
        )


def test_request_action_delegates_to_client(monkeypatch: pytest.MonkeyPatch):
    """Request action delegates method, route, body, and headers to OpenSearchClient."""
    constructed_options = []
    calls = []

    class FakeResponse:
        status_code = 201
        text = '{"result":"updated"}'

    class FakeClient:
        def __init__(self, **options):
            constructed_options.append(options)

        def request(self, method: str, route: str, body, headers=None):
            calls.append((method, route, body, headers))
            return FakeResponse()

    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", FakeClient)

    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(
        ctx.on.action(
            "request",
            params={
                "method": "PUT",
                "route": "/orders/_doc/1",
                "body": '{"title":"hello"}',
                "headers": '{"x-test":"true"}',
            },
        ),
        testing.State(),
    )

    assert constructed_options == [{"timeout": 30}]
    assert calls == [("PUT", "/orders/_doc/1", {"title": "hello"}, {"x-test": "true"})]
    assert ctx.action_results == {
        "status-code": 201,
        "body": '{"result":"updated"}',
    }


def test_request_action_uses_empty_default_body(monkeypatch: pytest.MonkeyPatch):
    """Request action passes an empty body when the body param is omitted."""
    constructed_options = []
    calls = []

    class FakeResponse:
        status_code = 200
        text = '{"status":"green"}'

    class FakeClient:
        def __init__(self, **options):
            constructed_options.append(options)

        def request(self, method: str, route: str, body, headers=None):
            calls.append((method, route, body, headers))
            return FakeResponse()

    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", FakeClient)

    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(
        ctx.on.action(
            "request",
            params={
                "method": "GET",
                "route": "/_cluster/health",
            },
        ),
        testing.State(),
    )

    assert constructed_options == [{"timeout": 30}]
    assert calls == [("GET", "/_cluster/health", None, None)]
    assert ctx.action_results == {
        "status-code": 200,
        "body": '{"status":"green"}',
    }


def test_bulk_insert_action_returns_compact_summary(monkeypatch: pytest.MonkeyPatch):
    """Bulk insert action returns item counts without the full bulk response body."""
    constructed_options = []
    calls = []

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "took": 7,
                "errors": True,
                "items": [
                    {"index": {"status": 201}},
                    {"index": {"status": 409, "error": {"type": "version_conflict"}}},
                ],
            }

    class FakeClient:
        def __init__(self, **options):
            constructed_options.append(options)

        def bulk_insert(self, index_names, docs_count, blob_size, route):
            calls.append((index_names, docs_count, blob_size, route))
            return FakeResponse()

    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", FakeClient)

    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(
        ctx.on.action(
            "bulk-insert",
            params={
                "index-names": '["zstd-index", "default-index"]',
                "docs-count": 5000,
                "blob-size": 100,
            },
        ),
        testing.State(),
    )

    assert constructed_options == [{"timeout": 30}]
    assert calls == [(["zstd-index", "default-index"], 5000, 100, "/_bulk")]
    assert ctx.action_results == {
        "status-code": 200,
        "result": {
            "took": 7,
            "errors": True,
            "success": 1,
            "failed": 1,
        },
    }


def test_request_action_params_default_timeout():
    """Request action params default to a 30 second timeout."""
    params = RequestActionParams.model_validate({"method": "GET", "route": "/"})

    assert params.client_options() == {"timeout": 30}


def test_generate_bulk_training_data_action_params_defaults():
    """KNN training-data action params mirror the helper defaults."""
    params = GenerateBulkTrainingDataActionParams.model_validate(
        {"index-name": "training-index", "vector-name": "embedding"}
    )

    assert params.index_name == "training-index"
    assert params.vector_name == "embedding"
    assert params.docs_count == 100
    assert params.dimensions == 4
    assert params.has_result is False
    assert params.client_options() == {}


def test_generate_bulk_training_data_action_overrides_configured_connection_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    """generate-bulk-training-data connection params override configured client options."""
    constructed_options = []
    calls = []
    ca_cert_path = tmp_path / "training_data_ca_cert.pem"
    ca_cert = "-----BEGIN CERTIFICATE-----\ntraining-cert\n-----END CERTIFICATE-----\n"

    class FakeClient:
        def __init__(self, **options):
            constructed_options.append(options)

        def create_bulk_training_data(self, **kwargs):
            calls.append(("create_bulk_training_data", kwargs))
            return {"took": 7, "errors": False, "items": [{}, {}]}, [1.0, 2.0]

    monkeypatch.setattr("charm.CA_CERTS_PATH", str(ca_cert_path))
    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", FakeClient)

    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(
        ctx.on.action(
            "generate-bulk-training-data",
            params={
                "index-name": "training-index",
                "vector-name": "embedding",
                "docs-count": 2,
                "dimensions": 2,
                "has-result": True,
                "host": "10.1.2.4",
                "username": "training-user",
                "password": "training-pass",
                "ca-cert": base64.b64encode(ca_cert.encode()).decode(),
            },
        ),
        testing.State(
            config={
                "opensearch-client-options": (
                    '{"host": "10.1.2.3", '
                    '"username": "config-user", '
                    '"password": "config-pass", '
                    '"timeout": 30}'
                )
            }
        ),
    )

    assert constructed_options == [
        {
            "host": "10.1.2.4",
            "username": "training-user",
            "password": "training-pass",
            "timeout": 30,
        }
    ]
    assert ca_cert_path.read_text() == ca_cert
    assert calls == [
        (
            "create_bulk_training_data",
            {
                "index_name": "training-index",
                "vector_name": "embedding",
                "docs_count": 2,
                "dimensions": 2,
                "has_result": True,
            },
        )
    ]


def test_generate_bulk_training_data_action_delegates_to_client(
    monkeypatch: pytest.MonkeyPatch,
):
    """generate-bulk-training-data reports the bulk insert response summary."""
    constructed_options = []
    calls = []

    class FakeClient:
        def __init__(self, **options):
            constructed_options.append(options)

        def create_bulk_training_data(self, **kwargs):
            calls.append(("create_bulk_training_data", kwargs))
            return {"took": 11, "errors": False, "items": [{}, {}]}, [1.0, 2.0]

    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", FakeClient)

    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(
        ctx.on.action(
            "generate-bulk-training-data",
            params={
                "index-name": "training-index",
                "vector-name": "embedding",
                "docs-count": 2,
                "dimensions": 2,
                "has-result": True,
            },
        ),
        testing.State(),
    )

    assert constructed_options == [{}]
    assert calls == [
        (
            "create_bulk_training_data",
            {
                "index_name": "training-index",
                "vector_name": "embedding",
                "docs_count": 2,
                "dimensions": 2,
                "has_result": True,
            },
        )
    ]
    assert ctx.action_results == {
        "result": {"took": 11, "errors": False, "success": 2},
        "vector": "[1.0, 2.0]",
    }


def test_request_action_overrides_configured_connection_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    """Request action connection params override configured client options."""
    constructed_options = []
    calls = []
    ca_cert_path = tmp_path / "request_ca_cert.pem"
    ca_cert = "-----BEGIN CERTIFICATE-----\nrequest-cert\n-----END CERTIFICATE-----\n"

    class FakeResponse:
        status_code = 200
        text = '{"ok":true}'

    class FakeClient:
        def __init__(self, **options):
            constructed_options.append(options)

        def request(self, method: str, route: str, body, headers=None):
            calls.append((method, route, body, headers))
            return FakeResponse()

    monkeypatch.setattr("charm.CA_CERTS_PATH", str(ca_cert_path))
    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", FakeClient)

    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(
        ctx.on.action(
            "request",
            params={
                "method": "GET",
                "route": "/_cluster/health",
                "host": "10.1.2.4",
                "username": "request-user",
                "password": "request-pass",
                "ca-cert": base64.b64encode(ca_cert.encode()).decode(),
                "timeout": 5,
            },
        ),
        testing.State(
            config={
                "opensearch-client-options": (
                    '{"host": "10.1.2.3", '
                    '"username": "config-user", '
                    '"password": "config-pass", '
                    '"timeout": 30}'
                )
            }
        ),
    )

    assert ca_cert_path.read_text() == ca_cert
    assert constructed_options == [
        {
            "host": "10.1.2.4",
            "username": "request-user",
            "password": "request-pass",
            "timeout": 5,
        }
    ]
    assert calls == [("GET", "/_cluster/health", None, None)]


def test_request_action_rejects_invalid_override_ca_cert():
    """Request action CA cert override must be valid base64."""
    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)

    with pytest.raises(UncaughtCharmError, match="ca-cert must be a valid base64-encoded string"):
        ctx.run(
            ctx.on.action(
                "request",
                params={
                    "method": "GET",
                    "route": "/_cluster/health",
                    "ca-cert": "not base64",
                },
            ),
            testing.State(),
        )


def test_request_action_rejects_non_json_body():
    """Request action body must be valid JSON when provided."""
    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)

    with pytest.raises(UncaughtCharmError, match="body must be valid JSON"):
        ctx.run(
            ctx.on.action(
                "request",
                params={
                    "method": "PUT",
                    "route": "/orders/_doc/1",
                    "body": "{not-json}",
                },
            ),
            testing.State(),
        )


def test_action_params_reject_non_positive_counts():
    """Action count params must be positive integers."""
    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)

    with pytest.raises(UncaughtCharmError, match="greater than or equal to 1"):
        ctx.run(
            ctx.on.action("create-dummy-docs", params={"count": 0}),
            testing.State(),
        )


def test_config_rejects_invalid_log_level():
    """Charm config validation rejects unknown log levels."""
    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)

    with pytest.raises(UncaughtCharmError, match="log-level must be one of"):
        ctx.run(ctx.on.config_changed(), testing.State(config={"log-level": "verbose"}))


def test_create_dummy_docs_action_overrides_configured_connection_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    """create-dummy-docs connection params override configured client options."""
    constructed_options = []
    calls = []
    ca_cert_path = tmp_path / "create_dummy_docs_ca_cert.pem"
    ca_cert = "-----BEGIN CERTIFICATE-----\ndocs-cert\n-----END CERTIFICATE-----\n"

    class FakeClient:
        def __init__(self, **options):
            constructed_options.append(options)

        def create_dummy_docs(self, **kwargs):
            calls.append(("create_dummy_docs", kwargs))
            return {"took": 7, "errors": False, "items": [{}, {}, {}, {}]}

    monkeypatch.setattr("charm.CA_CERTS_PATH", str(ca_cert_path))
    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", FakeClient)

    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(
        ctx.on.action(
            "create-dummy-docs",
            params={
                "count": 4,
                "host": "10.1.2.4",
                "username": "doc-user",
                "password": "doc-pass",
                "ca-cert": base64.b64encode(ca_cert.encode()).decode(),
            },
        ),
        testing.State(
            config={
                "opensearch-client-options": (
                    '{"host": "10.1.2.3", '
                    '"username": "config-user", '
                    '"password": "config-pass", '
                    '"timeout": 30}'
                )
            }
        ),
    )

    assert constructed_options == [
        {
            "host": "10.1.2.4",
            "username": "doc-user",
            "password": "doc-pass",
            "timeout": 30,
        }
    ]
    assert ca_cert_path.read_text() == ca_cert
    assert calls == [("create_dummy_docs", {"count": 4})]


def test_create_dummy_docs_action_delegates_to_client(monkeypatch: pytest.MonkeyPatch):
    """create-dummy-docs calls the client helper and reports the bulk response summary."""
    constructed_options = []
    calls = []

    class FakeClient:
        def __init__(self, **options):
            constructed_options.append(options)

        def create_dummy_docs(self, **kwargs):
            calls.append(("create_dummy_docs", kwargs))
            return {"took": 11, "errors": False, "items": [{}, {}, {}, {}]}

    monkeypatch.setattr("charm.opensearch_client.OpenSearchClient", FakeClient)

    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)
    ctx.run(ctx.on.action("create-dummy-docs", params={"count": 4}), testing.State())

    assert constructed_options == [{}]
    assert calls == [("create_dummy_docs", {"count": 4})]
    assert ctx.action_results == {"result": {"took": 11, "errors": False, "success": 4}}


def test_create_dummy_docs_action_rejects_invalid_override_ca_cert():
    """create-dummy-docs CA cert override must be valid base64."""
    ctx = testing.Context(DummyClientCharmCharm, actions=ACTIONS, config=CONFIG)

    with pytest.raises(UncaughtCharmError, match="ca-cert must be a valid base64-encoded string"):
        ctx.run(
            ctx.on.action(
                "create-dummy-docs",
                params={"count": 4, "ca-cert": "not base64"},
            ),
            testing.State(),
        )
