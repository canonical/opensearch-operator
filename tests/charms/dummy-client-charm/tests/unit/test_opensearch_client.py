#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for the dummy OpenSearch requests client."""

from typing import Any

import pytest

import opensearch_client
from models import CA_CERTS_PATH
from opensearch_client import OpenSearchClient


class FakeResponse:
    """Small response object for requests-backed client tests."""

    def __init__(self, payload: dict[str, Any] | None = None, status_code: int = 200):
        self._payload = payload or {}
        self.status_code = status_code
        self.text = str(self._payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}: {self.text}")


class FakeSession:
    """Record requests made by OpenSearchClient."""

    def __init__(self):
        self.auth: tuple[str | None, str | None] | None = None
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.responses: list[FakeResponse] = []
        self.failures: dict[tuple[str, str], int] = {}

    def request(self, method: str, url: str, **kwargs):
        key = (method, url)
        failures = self.failures.get(key, 0)
        if failures:
            self.failures[key] = failures - 1
            raise RuntimeError(f"{method} {url} failed")

        self.calls.append((method, url, kwargs))
        if self.responses:
            return self.responses.pop(0)
        return FakeResponse({"acknowledged": True})

    def head(self, url: str, **kwargs):
        return self.request("HEAD", url, **kwargs)


def test_initializes_requests_session(monkeypatch: pytest.MonkeyPatch):
    """Initializes a requests session with connection settings."""
    session = FakeSession()
    monkeypatch.setattr(opensearch_client.requests, "Session", lambda: session)

    client = OpenSearchClient(
        host="10.1.2.3",
        username="admin",
        password="secret",
        timeout=30,
    )
    session.responses.append(FakeResponse({"cluster_name": "test-cluster"}))

    assert client.request("GET", "/").json() == {"cluster_name": "test-cluster"}
    assert session.auth == ("admin", "secret")
    assert session.calls == [
        (
            "GET",
            "https://10.1.2.3:9200/",
            {"timeout": 30, "verify": CA_CERTS_PATH},
        )
    ]


def test_host_normalization_always_uses_https():
    """Single host inputs are normalized to explicit HTTPS OpenSearch base URLs."""
    session = FakeSession()

    client = OpenSearchClient(
        host={"host": "10.1.2.3", "port": 9201},
        session=session,
    )
    client.request("GET", "/")

    assert session.calls[0][1] == "https://10.1.2.3:9201/"

    session = FakeSession()
    client = OpenSearchClient(host="https://10.1.2.4:9202", session=session)
    client.request("GET", "/")

    assert session.calls[0][1] == "https://10.1.2.4:9202/"


def test_rejects_http_host_urls():
    """Configured OpenSearch hosts must use HTTPS."""
    with pytest.raises(ValueError, match="host URL must use https"):
        OpenSearchClient(host="http://10.1.2.3:9200", session=FakeSession())


def test_create_dummy_docs_uses_bulk_endpoint():
    """Create dummy docs action helper generates NDJSON and posts to _bulk."""
    session = FakeSession()
    session.responses = [FakeResponse({"errors": False})]
    client = OpenSearchClient(host="10.1.2.3", session=session)

    result = client.create_dummy_docs(count=1)
    bulk_payload = session.calls[0][2]["data"]

    assert result == {"errors": False}
    assert session.calls == [
        (
            "POST",
            "https://10.1.2.3:9200/_bulk",
            {
                "data": bulk_payload,
                "headers": {"Content-Type": "application/x-ndjson"},
                "timeout": None,
                "verify": CA_CERTS_PATH,
            },
        )
    ]
    assert '"create":{"_index":"index_0", "_id":"0"}' in bulk_payload
    assert '"ProductId": "1000"' in bulk_payload


def test_generate_bulk_training_data_returns_deterministic_ndjson_and_vectors():
    """KNN training data generation mirrors the deterministic bulk helper."""
    bulk_payload, vectors = opensearch_client.generate_bulk_training_data(
        index_name="training-index",
        vector_name="embedding",
        docs_count=2,
        dimensions=3,
        has_result=True,
    )

    assert bulk_payload == (
        '{"index": {"_index": "training-index", "_id": 0}}\n'
        '{"embedding": [254.0, 110.0, 99.0], "price": 152.0}\n'
        '{"index": {"_index": "training-index", "_id": 1}}\n'
        '{"embedding": [35.0, 19.0, 15.0], "price": 60.0}\n'
    )
    assert vectors == [[254.0, 110.0, 99.0], [35.0, 19.0, 15.0]]


def test_create_bulk_training_data_uses_bulk_endpoint():
    """KNN training data is generated and posted to the bulk endpoint."""
    session = FakeSession()
    session.responses = [FakeResponse({"took": 8, "errors": False, "items": [{}, {}]})]
    client = OpenSearchClient(host="10.1.2.3", session=session)

    result, vector = client.create_bulk_training_data(
        index_name="training-index",
        vector_name="embedding",
        docs_count=2,
        dimensions=3,
        has_result=True,
    )
    bulk_payload = session.calls[0][2]["data"]

    assert result == {"took": 8, "errors": False, "items": [{}, {}]}
    assert vector == [254.0, 110.0, 99.0]
    assert session.calls == [
        (
            "POST",
            "https://10.1.2.3:9200/_bulk",
            {
                "data": bulk_payload,
                "headers": {"Content-Type": "application/x-ndjson"},
                "timeout": None,
                "verify": CA_CERTS_PATH,
            },
        )
    ]
    assert bulk_payload == (
        '{"index": {"_index": "training-index", "_id": 0}}\n'
        '{"embedding": [254.0, 110.0, 99.0], "price": 152.0}\n'
        '{"index": {"_index": "training-index", "_id": 1}}\n'
        '{"embedding": [35.0, 19.0, 15.0], "price": 60.0}\n'
    )


def test_generic_request_uses_configured_opensearch_connection():
    """Generic requests reuse the configured session, TLS, timeout, and base URL."""
    session = FakeSession()
    session.responses = [FakeResponse({"updated": True}, status_code=201)]
    client = OpenSearchClient(
        host="10.1.2.3",
        timeout=30,
        session=session,
    )

    response = client.request("put", "/orders/_doc/1", {"title": "hello"})

    assert response.status_code == 201
    assert response.json() == {"updated": True}
    assert session.calls == [
        (
            "PUT",
            "https://10.1.2.3:9200/orders/_doc/1",
            {
                "json": {"title": "hello"},
                "timeout": 30,
                "verify": CA_CERTS_PATH,
            },
        )
    ]


def test_generic_request_sends_raw_string_body_as_data():
    """Generic requests preserve string bodies for NDJSON and other raw payloads."""
    session = FakeSession()
    client = OpenSearchClient(host="10.1.2.3", session=session)
    body = '{"create":{"_index":"index_0","_id":"1"}}\n{"title":"hello"}\n'

    client.request("POST", "/_bulk", body)

    assert session.calls == [
        (
            "POST",
            "https://10.1.2.3:9200/_bulk",
            {"data": body, "timeout": None, "verify": CA_CERTS_PATH},
        )
    ]


def test_bulk_insert_generates_documents_for_each_index():
    """Generated bulk inserts create the same deterministic documents per index."""
    session = FakeSession()
    client = OpenSearchClient(host="10.1.2.3", session=session)

    client.bulk_insert(["zstd-index", "default-index"], docs_count=2, blob_size=3)

    assert session.calls == [
        (
            "PUT",
            "https://10.1.2.3:9200/_bulk",
            {
                "data": (
                    '{"index": {"_index": "zstd-index"}}\n'
                    '{"x": 0, "blob": "AAA"}\n'
                    '{"index": {"_index": "zstd-index"}}\n'
                    '{"x": 1, "blob": "AAA"}\n'
                    '{"index": {"_index": "default-index"}}\n'
                    '{"x": 0, "blob": "AAA"}\n'
                    '{"index": {"_index": "default-index"}}\n'
                    '{"x": 1, "blob": "AAA"}\n'
                ),
                "headers": {"Content-Type": "application/x-ndjson"},
                "timeout": None,
                "verify": CA_CERTS_PATH,
            },
        )
    ]


def test_generic_request_forwards_headers():
    """Generic requests can forward caller-supplied headers."""
    session = FakeSession()
    client = OpenSearchClient(host="10.1.2.3", session=session)

    client.request("POST", "/_dashboards/api/saved_objects", {"ok": True}, {"osd-xsrf": "true"})

    assert session.calls == [
        (
            "POST",
            "https://10.1.2.3:9200/_dashboards/api/saved_objects",
            {
                "headers": {"osd-xsrf": "true"},
                "json": {"ok": True},
                "timeout": None,
                "verify": CA_CERTS_PATH,
            },
        )
    ]


def test_generic_request_accepts_full_urls_and_empty_body():
    """Generic requests can use a full URL and omit the request body."""
    session = FakeSession()
    client = OpenSearchClient(host="10.1.2.3", session=session)

    client.request("GET", "https://10.1.2.4:9201/_cluster/health", None)

    assert session.calls == [
        (
            "GET",
            "https://10.1.2.4:9201/_cluster/health",
            {"timeout": None, "verify": CA_CERTS_PATH},
        )
    ]


def test_generic_request_rejects_http_urls():
    """Generic request full URLs must use HTTPS."""
    client = OpenSearchClient(host="10.1.2.3", session=FakeSession())

    with pytest.raises(ValueError, match="request URL must use https"):
        client.request("GET", "http://10.1.2.4:9201/_cluster/health")


def test_create_dummy_docs_propagates_bulk_request_failures():
    """create-dummy-docs propagates bulk request failures."""
    session = FakeSession()
    client = OpenSearchClient(host="10.1.2.3", session=session)

    session.failures = {("POST", "https://10.1.2.3:9200/_bulk"): 2}

    with pytest.raises(RuntimeError, match="POST https://10.1.2.3:9200/_bulk failed"):
        client.create_dummy_docs(count=1)

    assert session.failures == {("POST", "https://10.1.2.3:9200/_bulk"): 1}
    assert session.calls == []
