# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Functions for managing and interacting with the workload.

The intention is that this module could be used outside the context of a charm.
"""

import json
import logging
import random
from collections.abc import Mapping
from random import randint
from typing import Any, Protocol, cast
from urllib.parse import quote, urlsplit

import requests

from models import CA_CERTS_PATH, ClientHost

logger = logging.getLogger(__name__)


def generate_bulk_training_data(
    index_name: str,
    vector_name: str,
    docs_count: int = 100,
    dimensions: int = 4,
    has_result: bool = False,
) -> tuple[str, list[list[float]]]:
    """Generate deterministic NDJSON documents and vectors for KNN training."""
    random.seed("seed")

    data = random.randbytes(docs_count * dimensions)
    responses = random.randbytes(docs_count) if has_result else b""
    result = ""
    result_list: list[list[float]] = []
    for i in range(docs_count):
        result += json.dumps({"index": {"_index": index_name, "_id": i}}) + "\n"
        result_list.append([float(data[j]) for j in range(i * dimensions, (i + 1) * dimensions)])
        document: dict[str, float | list[float]] = {vector_name: result_list[i]}
        if has_result:
            document["price"] = float(responses[i])
        result += json.dumps(document) + "\n"
    return result, result_list


class HttpSession(Protocol):
    """Minimal requests session protocol used by OpenSearchClient."""

    auth: Any

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Send an HTTP request."""


class OpenSearchClient:
    """Small requests-backed client for the charm actions."""

    def __init__(
        self,
        host: ClientHost | Mapping[str, Any] | str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: int | None = None,
        verify: str | bool | None = None,
        session: HttpSession | None = None,
    ) -> None:
        """Initialize an OpenSearch HTTP client."""
        if host is None:
            raise ValueError("host must be provided")

        self._base_url = self._normalize_host(host)
        self._session: HttpSession = session or cast(HttpSession, requests.Session())
        self._timeout = timeout
        self._verify: str | bool = CA_CERTS_PATH if verify is None else verify
        if username is not None or password is not None:
            self._session.auth = (username or "", password or "")

    @staticmethod
    def _normalize_host(host: ClientHost | Mapping[str, Any] | str) -> str:
        """Return a single host definition as an HTTPS base URL."""
        if isinstance(host, str):
            parsed = urlsplit(host)
            if parsed.scheme:
                if parsed.scheme != "https":
                    raise ValueError("host URL must use https")
                return host.rstrip("/")
            return f"https://{host}:9200"

        if isinstance(host, ClientHost):
            return f"https://{host.host}:{host.port}"
        return f"https://{host['host']}:{host['port']}"

    def _url(self, *parts: str | int) -> str:
        """Build an OpenSearch URL for a path."""
        if not parts:
            return f"{self._base_url}/"
        path = "/".join(quote(str(part), safe="") for part in parts)
        return f"{self._base_url}/{path}"

    def _request(self, method: str, *parts: str | int, **kwargs: Any) -> requests.Response:
        """Send a request to OpenSearch and raise for unsuccessful responses."""
        url = self._resolve_url(str(parts[0])) if len(parts) == 1 else self._url(*parts)
        request_kwargs: dict[str, Any] = {
            "timeout": self._timeout,
            "verify": self._verify,
        }
        request_kwargs.update(kwargs)
        response = self._session.request(method.upper(), url, **request_kwargs)
        return response

    def request(
        self,
        method: str,
        route: str,
        body: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> requests.Response:
        """Send a generic OpenSearch request."""
        request_kwargs: dict[str, Any] = {}
        if headers:
            request_kwargs["headers"] = headers
        if body is not None:
            if isinstance(body, str):
                request_kwargs["data"] = body
            else:
                request_kwargs["json"] = body
        return self._request(method, route, **request_kwargs)

    def _resolve_url(self, url: str) -> str:
        """Return absolute HTTPS URLs unchanged and resolve paths against the client host."""
        parsed = urlsplit(url)
        if parsed.scheme == "https":
            return url
        if parsed.scheme:
            raise ValueError("request URL must use https")
        return f"{self._base_url}/{url.lstrip('/')}"

    def create_dummy_docs(self, count: int = 5) -> dict[str, Any]:
        """Store generated documents in the dummy indexes."""
        all_docs = ""
        for index_id in range(count):
            for doc_id in range(count * 1000):
                all_docs = (
                    f"{all_docs}"
                    f'{{"create":{{"_index":"index_{index_id}", "_id":"{doc_id}"}}}}\n'
                    f'{{"ProductId": "{1000 + doc_id}", '
                    f'"Amount": "{randint(10, 1000)}", '
                    f'"Quantity": "{randint(0, 50)}", '
                    f'"Store_Id": "{randint(1, 250)}"}}\n'
                )

        return self._request(
            "POST",
            "_bulk",
            data=all_docs,
            headers={"Content-Type": "application/x-ndjson"},
        ).json()

    def bulk_insert(
        self,
        index_names: list[str],
        docs_count: int,
        blob_size: int,
        route: str = "/_bulk",
    ) -> requests.Response:
        """Generate deterministic documents and store them through the bulk endpoint."""
        blob = "A" * blob_size
        lines = []
        for index_name in index_names:
            for doc_id in range(docs_count):
                lines.append(json.dumps({"index": {"_index": index_name}}))
                lines.append(json.dumps({"x": doc_id, "blob": blob}))
        body = "\n".join(lines) + "\n"
        return self._request(
            "PUT",
            route,
            data=body,
            headers={"Content-Type": "application/x-ndjson"},
        )

    def create_bulk_training_data(
        self,
        index_name: str,
        vector_name: str,
        docs_count: int = 100,
        dimensions: int = 4,
        has_result: bool = False,
    ) -> tuple[dict[str, Any], list[float]]:
        """Generate KNN training data and store it through the bulk endpoint."""
        all_docs, result_list = generate_bulk_training_data(
            index_name=index_name,
            vector_name=vector_name,
            docs_count=docs_count,
            dimensions=dimensions,
            has_result=has_result,
        )
        response = self._request(
            "POST",
            "_bulk",
            data=all_docs,
            headers={"Content-Type": "application/x-ndjson"},
        ).json()
        return response, result_list[0]
