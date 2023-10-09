# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""
import logging
from typing import Dict, List

from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchError,
    OpenSearchHttpError,
)

# The unique Charmhub library identifier, never change it
LIBID = "de98efa151804b699d5d6128fa100807"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class OpenSearchKeystoreError(OpenSearchError):
    """Exception thrown when an opensearch keystore is invalid."""


class OpenSearchKeystore:
    """Manages keystore."""

    KEYSTORE = "opensearch-keystore"

    def __init__(self, charm):
        """Creates the keystore manager class."""
        self._charm = charm
        self._opensearch = charm.opensearch

    def add(self, entries: Dict[str, str]) -> None:
        """Adds a given key to the "opensearch" keystore."""
        if not entries:
            return  # no key/value to add, no need to request reload of keystore either
        for key, value in entries.items():
            self._add(key, value)
        self._reload_keystore()

    def delete(self, entries: List[str]) -> None:
        """Removes a given key from "opensearch" keystore."""
        if not entries:
            return  # no key/value to remove, no need to request reload of keystore either
        for key in entries:
            self._delete(key)
        self._reload_keystore()

    def list(self) -> List[str]:
        """Lists the keys available in opensearch's keystore."""
        try:
            return self._opensearch.run_bin("opensearch-keystore", "list").split("\n")
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    def _add(self, key: str, value: str):
        if not value:
            raise OpenSearchKeystoreError("Missing keystore value")
        try:
            # Add newline to the end of the key, if missing
            value += "" if value.endswith("\n") else "\n"
            self._opensearch.run_bin("opensearch-keystore", f"add --force {key}", stdin=value)
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    def _delete(self, key: str) -> None:
        try:
            self._opensearch.run_bin("opensearch-keystore", f"remove {key}")
        except OpenSearchCmdError as e:
            if "does not exist in the keystore" in str(e):
                logger.info(
                    "opensearch_keystore._delete:"
                    f" Key {key} not found in keystore, continuing..."
                )
                return
            raise OpenSearchKeystoreError(str(e))

    def _reload_keystore(self) -> None:
        """Updates the keystore value (adding or removing) and reload."""
        try:
            # Reload the security settings and return if opensearch needs restart
            response = self._opensearch.request("POST", "_nodes/reload_secure_settings")
            logger.debug(f"_update_keystore_and_reload: response received {response}")
        except OpenSearchHttpError as e:
            raise OpenSearchKeystoreError(
                f"Failed to reload keystore: error code: {e.response_code}, error body: {e.response_body}"
            )
