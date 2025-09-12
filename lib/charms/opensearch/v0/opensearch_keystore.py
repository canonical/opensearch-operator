# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""
import logging
from typing import Any, Dict

from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
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

KEYSTORE = "keystore"


class OpenSearchKeystore:
    """Manages keystore."""

    def __init__(self, opensearch):
        """Creates the keystore manager class."""
        self._opensearch = opensearch

    def update(self, entries: Dict[str, Any]) -> None:
        """Updates the keystore value (adding or removing)"""
        if not entries:
            return

        for key, value in entries.items():
            if value:
                self.add(key, value)
            else:
                self.delete(key)

    def add(self, key: str, value: str):
        """Adds key, value pair to OpenSearch keystore"""
        self._opensearch.run_bin(KEYSTORE, f"add --force --stdin {key}", stdin=value)

    def delete(self, key: str) -> None:
        """Deletes key from OpenSearch keystore if it exists"""
        try:
            self._opensearch.run_bin(KEYSTORE, f"remove {key}")
        except OpenSearchCmdError as e:
            if "does not exist in the keystore" in str(e):
                logger.info("Keystore command 'delete' failed for key: %s. Key not found.", key)
                return
            raise

    def reload(self):
        """Reloads local node's secure settings

        Raises:
            OpenSearchHttpError: If the reload fails.
        """
        try:
            response = self._opensearch.request("POST", "_nodes/_local/reload_secure_settings")
        except OpenSearchHttpError:
            logger.info("Could not request secure settings reload.")
            return False
        failed = response.get("_nodes", {}).get("failed", -1)
        return failed == 0
