# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""
import logging
import os

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
        self._keystore_path = f"{opensearch.paths.conf}/opensearch.keystore"

    def _create_if_needed(self) -> None:
        """Creates the keystore if not already present."""
        if os.path.exists(self._keystore_path):
            return

        self._opensearch.run_bin(KEYSTORE, "create")

    def add_entries(self, entries: dict[str, str]) -> None:
        """Adds given entries to OpenSearch keystore"""
        for key, value in entries.items():
            self._opensearch.run_bin(KEYSTORE, f"add --force --stdin {key}", stdin=value)

    def remove_entries(self, keys: list[str]) -> None:
        """Removes entries from OpenSearch keystore"""
        self._create_if_needed()
        for key in keys:
            try:
                self._opensearch.run_bin(KEYSTORE, f"remove {key}")
            except OpenSearchCmdError as e:
                if e.err and "does not exist in the keystore" in e.err:
                    continue
                raise

    def reload(self) -> bool:
        """Reloads local node's secure settings

        Raises:
            OpenSearchHttpError: If the reload fails.
        """
        if not self._opensearch.is_started():
            # service not running, settings will be picked up at startup
            return True

        try:
            response = self._opensearch.request("POST", "_nodes/_local/reload_secure_settings")
        except OpenSearchHttpError as e:
            logger.error("Could not reload secure settings: %s", e)
            return False

        failed = response.get("_nodes", {}).get("failed", -1)
        return failed == 0
