# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""
import functools
import logging
import os
from typing import Any, Dict, List

from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchError,
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


class OpenSearchKeystoreNotReadyError(OpenSearchKeystoreError):
    """Exception thrown when the keystore is not ready yet."""


class OpenSearchKeystore:
    """Manages keystore."""

    def __init__(self, opensearch: "OpenSearchDistribution"):
        """Creates the keystore manager class."""
        self._opensearch = opensearch
        self._keystore = "keystore"
        self._keystore_path = f"{opensearch.paths.conf}/opensearch.keystore"

    def _create_if_needed(self) -> None:
        """Creates the keystore if not already present."""
        if os.path.exists(self._keystore_path):
            return

        self._opensearch.run_bin("keystore", "create")

    def put_entries(self, entries: dict[str, str]) -> None:
        """Add new key/val entries on the keystore."""
        for key, val in entries.items():
            # adding the '--force' flag will create the keystore if not present
            self._opensearch.run_bin("keystore", f"add {key} --force", stdin=val)

    def put_file_entry(self, key: str, filename: str) -> None:
        """Add a new file entry in the keystore."""
        self._opensearch.run_bin("keystore", f"add-file {key} {filename} --force")

    def remove_entries(self, keys: list[str]) -> None:
        """Remove entries from the keystore."""
        self._create_if_needed()

        for key in keys:
            if key == "keystore.seed":
                continue

            try:
                self._opensearch.run_bin("keystore", f"remove {key}")
            except OpenSearchCmdError as e:
                if e.err and "does not exist in the keystore" in e.err:
                    continue
                raise

    def list_keys(self) -> list[str]:
        """List all keys in the keystore."""
        self._create_if_needed()
        return self._opensearch.run_bin("keystore", "list").splitlines()

    def reload(self) -> None:
        """Reload the keystore."""
        self._create_if_needed()
        self._opensearch.run_bin("keystore", "upgrade")

        if self._opensearch.is_node_up():
            self._opensearch.request("POST", "_nodes/reload_secure_settings")
            logger.debug("keystore reloaded.")

    # TODO delete once backups rework fully merged
    def update(self, entries: Dict[str, Any]) -> None:
        """Updates the keystore value (adding or removing) and reload.

        Raises:
            OpenSearchHttpError: If the reload fails.
        """
        if not os.path.exists(self._keystore_path):
            raise OpenSearchKeystoreNotReadyError()

        if not entries:
            return

        for key, value in entries.items():
            if value:
                self._add(key, value)
            else:
                self._delete(key)

    # TODO delete once backups rework fully merged
    @functools.cached_property
    def list(self) -> List[str]:
        """Lists the keys available in opensearch's keystore."""
        if not os.path.exists(self._keystore_path):
            raise OpenSearchKeystoreNotReadyError()
        try:
            return self._opensearch.run_bin(self._keystore, "list").split("\n")
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    # TODO delete once backups rework fully merged
    def _add(self, key: str, value: str):
        try:
            # Add newline to the end of the key, if missing
            value += "" if value.endswith("\n") else "\n"
            self._opensearch.run_bin(self._keystore, f"add --force {key}", stdin=value)

            self._clean_cache_if_needed()
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    # TODO delete once backups rework fully merged
    def _delete(self, key: str) -> None:
        try:
            self._opensearch.run_bin(self._keystore, f"remove {key}")

            self._clean_cache_if_needed()
        except OpenSearchCmdError as e:
            if "does not exist in the keystore" in str(e):
                logger.info(
                    "opensearch_keystore._delete:"
                    f" Key {key} not found in keystore, continuing..."
                )
                return
            raise OpenSearchKeystoreError(str(e))

    # TODO delete once backups rework fully merged
    def reload_keystore(self) -> None:
        """Updates the keystore value (adding or removing) and reload.

        This method targets only the local unit as alt_hosts is not set.

        Raises:
            OpenSearchHttpError: If the reload fails.
        """
        response = self._opensearch.request("POST", "_nodes/reload_secure_settings")
        logger.debug(f"_update_keystore_and_reload: response received {response}")

    # TODO delete once backups rework fully merged
    def _clean_cache_if_needed(self):
        """Delete keystore content cached property."""
        if self.list:
            del self.list
