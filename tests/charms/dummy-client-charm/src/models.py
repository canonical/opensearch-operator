# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Pydantic models for charm config and action params."""

import base64
import binascii
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

CA_CERTS_PATH = "/tmp/ca_cert.pem"
VALID_LOG_LEVELS = {"info", "debug", "warning", "error", "critical"}


class CharmModel(BaseModel):
    """Base model for charm validation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ClientHost(CharmModel):
    """OpenSearch host config."""

    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)


class ClientOptions(CharmModel):
    """Validated OpenSearch client options from charm config."""

    host: str | ClientHost | None = None
    username: str | None = None
    password: str | None = None
    timeout: int | None = Field(default=None, ge=1)

    def kwargs(self) -> dict[str, Any]:
        """Return only options explicitly configured by the user."""
        return self.model_dump(include=self.model_fields_set, exclude_none=True)


class CharmConfig(CharmModel):
    """Validated charm config."""

    log_level: str = Field(default="info", alias="log-level")
    opensearch_client_options: ClientOptions = Field(
        default_factory=ClientOptions,
        alias="opensearch-client-options",
    )
    ca_cert: str = Field(default="", alias="ca-cert")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Validate configured log level."""
        normalized = value.lower()
        if normalized not in VALID_LOG_LEVELS:
            levels = ", ".join(sorted(VALID_LOG_LEVELS))
            raise ValueError(f"log-level must be one of: {levels}")
        return normalized

    @field_validator("opensearch_client_options", mode="before")
    @classmethod
    def parse_client_options(cls, value: Any) -> Any:
        """Parse OpenSearch client options from their JSON config string."""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError("opensearch-client-options must be valid JSON") from exc

        if not isinstance(value, dict):
            raise ValueError("opensearch-client-options must be a JSON object")
        return value

    @field_validator("ca_cert")
    @classmethod
    def validate_ca_cert(cls, value: str) -> str:
        """Validate configured base64 CA certificate."""
        if not value:
            return value

        try:
            base64.b64decode(value, validate=True).decode()
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("ca-cert must be a valid base64-encoded string") from exc
        return value


class CreateDummyDocsActionParams(CharmModel):
    """Validated create-dummy-docs action params."""

    count: int = Field(default=5, ge=1)
    host: str | None = Field(default=None, min_length=1)
    username: str | None = None
    password: str | None = None
    ca_cert: str | None = Field(default=None, alias="ca-cert")

    def client_options(self) -> dict[str, Any]:
        """Return action-scoped client option overrides."""
        return self.model_dump(
            include={"host", "username", "password"},
            exclude_none=True,
        )

    @field_validator("ca_cert")
    @classmethod
    def validate_ca_cert(cls, value: str | None) -> str | None:
        """Validate action-scoped base64 CA certificate."""
        if not value:
            return value

        try:
            base64.b64decode(value, validate=True).decode()
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("ca-cert must be a valid base64-encoded string") from exc
        return value


class GenerateBulkTrainingDataActionParams(CharmModel):
    """Validated generate-bulk-training-data action params."""

    index_name: str = Field(alias="index-name", min_length=1)
    vector_name: str = Field(alias="vector-name", min_length=1)
    docs_count: int = Field(default=100, alias="docs-count", ge=1)
    dimensions: int = Field(default=4, ge=1)
    has_result: bool = Field(default=False, alias="has-result")
    host: str | None = Field(default=None, min_length=1)
    username: str | None = None
    password: str | None = None
    ca_cert: str | None = Field(default=None, alias="ca-cert")

    def client_options(self) -> dict[str, Any]:
        """Return action-scoped client option overrides."""
        return self.model_dump(
            include={"host", "username", "password"},
            exclude_none=True,
        )

    @field_validator("ca_cert")
    @classmethod
    def validate_ca_cert(cls, value: str | None) -> str | None:
        """Validate action-scoped base64 CA certificate."""
        if not value:
            return value

        try:
            base64.b64decode(value, validate=True).decode()
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("ca-cert must be a valid base64-encoded string") from exc
        return value


class BulkInsertActionParams(CharmModel):
    """Validated generated bulk insert action params."""

    index_names: list[str] = Field(alias="index-names", min_length=1)
    docs_count: int = Field(default=100, alias="docs-count", ge=1)
    blob_size: int = Field(default=100, alias="blob-size", ge=0)
    route: str = Field(default="/_bulk", min_length=1)
    host: str | None = Field(default=None, min_length=1)
    username: str | None = None
    password: str | None = None
    ca_cert: str | None = Field(default=None, alias="ca-cert")
    verify: bool = True
    timeout: int = Field(default=30, ge=1)

    def client_options(self) -> dict[str, Any]:
        """Return action-scoped client option overrides."""
        options = self.model_dump(
            include={"host", "username", "password", "timeout"},
            exclude_none=True,
        )
        if not self.verify:
            options["verify"] = False
        return options

    @field_validator("index_names", mode="before")
    @classmethod
    def parse_index_names(cls, value: Any) -> list[str]:
        """Parse JSON-encoded index names from action params."""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError("index-names must be a valid JSON list") from exc
        if not isinstance(value, list) or not value:
            raise ValueError("index-names must be a non-empty JSON list")
        names = [str(name).strip() for name in value]
        if any(not name for name in names):
            raise ValueError("index-names must not contain empty names")
        return names

    @field_validator("route")
    @classmethod
    def validate_route(cls, value: str) -> str:
        """Validate bulk route."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("route must not be empty")
        return stripped

    @field_validator("ca_cert")
    @classmethod
    def validate_ca_cert(cls, value: str | None) -> str | None:
        """Validate action-scoped base64 CA certificate."""
        if not value:
            return value

        try:
            base64.b64decode(value, validate=True).decode()
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("ca-cert must be a valid base64-encoded string") from exc
        return value


class RequestActionParams(CharmModel):
    """Validated generic request action params."""

    method: str = Field(min_length=1)
    route: str = Field(min_length=1)
    body: Any | None = None
    headers: dict[str, str] | None = None
    host: str | None = Field(default=None, min_length=1)
    username: str | None = None
    password: str | None = None
    ca_cert: str | None = Field(default=None, alias="ca-cert")
    verify: bool = True
    timeout: int = Field(default=30, ge=1)

    def client_options(self) -> dict[str, Any]:
        """Return request-scoped client option overrides."""
        options = self.model_dump(
            include={"host", "username", "password", "timeout"},
            exclude_none=True,
        )
        if not self.verify:
            options["verify"] = False
        return options

    @property
    def has_client_overrides(self) -> bool:
        """Return whether request-scoped client options were provided."""
        return bool(self.client_options() or self.ca_cert)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        """Normalize HTTP method."""
        return value.strip().upper()

    @field_validator("route")
    @classmethod
    def validate_route(cls, value: str) -> str:
        """Validate request route."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("route must not be empty")
        return stripped

    @field_validator("body", mode="before")
    @classmethod
    def parse_body(cls, value: Any) -> Any | None:
        """Parse optional JSON action body."""
        if value is None or value == "":
            return None
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError("body must be valid JSON") from exc

        try:
            json.dumps(value)
        except TypeError as exc:
            raise ValueError("body must be JSON serializable") from exc
        return value

    @field_validator("headers", mode="before")
    @classmethod
    def parse_headers(cls, value: Any) -> dict[str, str] | None:
        """Parse optional JSON action headers."""
        if value is None or value == "":
            return None
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError("headers must be valid JSON") from exc

        if not isinstance(value, dict):
            raise ValueError("headers must be a JSON object")
        return {str(key): str(header_value) for key, header_value in value.items()}

    @field_validator("ca_cert")
    @classmethod
    def validate_ca_cert(cls, value: str | None) -> str | None:
        """Validate request-scoped base64 CA certificate."""
        if not value:
            return value

        try:
            base64.b64decode(value, validate=True).decode()
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("ca-cert must be a valid base64-encoded string") from exc
        return value
