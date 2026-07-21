#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the application."""

import base64
import binascii
import json
import logging
from pathlib import Path
from typing import Any

import ops

# A standalone module for workload-specific logic (no charming concerns):
import opensearch_client
from models import (
    CA_CERTS_PATH,
    BulkInsertActionParams,
    CharmConfig,
    CreateDummyDocsActionParams,
    GenerateBulkTrainingDataActionParams,
    RequestActionParams,
)

logger = logging.getLogger(__name__)


class DummyClientCharmCharm(ops.CharmBase):
    """Charm the application."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        framework.observe(self.on.start, self._on_start)
        framework.observe(self.on.config_changed, self._on_config_changed)
        framework.observe(self.on.create_dummy_docs_action, self._on_create_dummy_docs_action)
        framework.observe(self.on.bulk_insert_action, self._on_bulk_insert_action)
        framework.observe(
            self.on.generate_bulk_training_data_action,
            self._on_generate_bulk_training_data_action,
        )
        framework.observe(self.on.request_action, self._on_request_action)

    def _on_start(self, _: ops.StartEvent) -> None:
        """Handle start event."""
        self.unit.status = ops.ActiveStatus()

    def _on_config_changed(self, event: ops.ConfigChangedEvent) -> None:
        """Handle config changed event."""
        config = self._charm_config()
        if config.ca_cert:
            self._write_ca_cert(config.ca_cert)

    def _on_create_dummy_docs_action(self, event: ops.ActionEvent) -> None:
        """Handle create-dummy-docs action."""
        params = CreateDummyDocsActionParams.model_validate(event.params)
        client = self._opensearch_client(params.client_options(), params.ca_cert)
        result = client.create_dummy_docs(
            count=params.count,
        )
        logger.debug(
            "results: %s",
            {
                "took": result["took"],
                "errors": result["errors"],
                "success": len(result["items"]),
            },
        )
        event.set_results(
            {
                "result": {
                    "took": result["took"],
                    "errors": result["errors"],
                    "success": len(result["items"]),
                }
            }
        )

    def _on_generate_bulk_training_data_action(self, event: ops.ActionEvent) -> None:
        """Handle generate-bulk-training-data action."""
        params = GenerateBulkTrainingDataActionParams.model_validate(event.params)
        client = self._opensearch_client(params.client_options(), params.ca_cert)
        result, vector = client.create_bulk_training_data(
            index_name=params.index_name,
            vector_name=params.vector_name,
            docs_count=params.docs_count,
            dimensions=params.dimensions,
            has_result=params.has_result,
        )
        logger.debug(
            "results: %s",
            {
                "took": result["took"],
                "errors": result["errors"],
                "success": len(result["items"]),
            },
        )
        event.set_results(
            {
                "result": {
                    "took": result["took"],
                    "errors": result["errors"],
                    "success": len(result["items"]),
                },
                "vector": json.dumps(vector),
            }
        )

    def _on_request_action(self, event: ops.ActionEvent) -> None:
        """Handle generic OpenSearch request action."""
        params = RequestActionParams.model_validate(event.params)
        client = self._opensearch_client(params.client_options(), params.ca_cert)
        response = client.request(
            method=params.method,
            route=params.route,
            body=params.body,
            headers=params.headers,
        )
        logger.debug(
            "Received response with status code %s and body: %s",
            response.status_code,
            response.text,
        )
        event.set_results({"status-code": response.status_code, "body": response.text})

    def _on_bulk_insert_action(self, event: ops.ActionEvent) -> None:
        """Handle generated bulk insert action."""
        params = BulkInsertActionParams.model_validate(event.params)
        client = self._opensearch_client(params.client_options(), params.ca_cert)
        response = client.bulk_insert(
            index_names=params.index_names,
            docs_count=params.docs_count,
            blob_size=params.blob_size,
            route=params.route,
        )
        result = response.json()
        event.set_results(
            {
                "status-code": response.status_code,
                "result": self._bulk_result_summary(result),
            }
        )

    @staticmethod
    def _bulk_result_summary(result: dict[str, Any]) -> dict[str, Any]:
        """Return a compact summary safe for Juju action results."""
        items = result.get("items", [])
        failed = 0
        for item in items:
            operation = next(iter(item.values()), {})
            status = operation.get("status", 0)
            if status >= 300 or "error" in operation:
                failed += 1
        return {
            "took": result.get("took", 0),
            "errors": result.get("errors", False),
            "success": len(items) - failed,
            "failed": failed,
        }

    def _charm_config(self) -> CharmConfig:
        """Return validated charm config."""
        return CharmConfig.model_validate(dict(self.config))

    def _opensearch_client(
        self,
        overrides: dict[str, Any] | None = None,
        ca_cert_b64: str | None = None,
    ) -> opensearch_client.OpenSearchClient:
        """Build an OpenSearch client from charm config."""
        config = self._charm_config()
        options = config.opensearch_client_options.kwargs()
        options.update(overrides or {})
        if ca_cert := ca_cert_b64 or config.ca_cert:
            self._write_ca_cert(ca_cert)
        return opensearch_client.OpenSearchClient(**options)

    @staticmethod
    def _write_ca_cert(ca_cert_b64: str) -> None:
        """Write a base64-encoded CA certificate to disk."""
        try:
            ca_cert = base64.b64decode(ca_cert_b64, validate=True).decode()
            logger.debug("Successfully decoded base64 CA certificate")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("ca-cert must be a valid base64-encoded string") from exc

        Path(CA_CERTS_PATH).write_text(ca_cert)


if __name__ == "__main__":  # pragma: nocover
    ops.main(DummyClientCharmCharm)
