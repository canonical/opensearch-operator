# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""
import functools
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List

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


class Keystore(ABC):
    """Abstract class that represents the keystore."""

    def __init__(self, charm, password: str = None):
        """Creates the keystore manager class."""
        self._charm = charm
        self._opensearch = charm.opensearch
        self._keystore = "keystore"
        self._keystore_path = ""

    @abstractmethod
    def update(self, entries: Dict[str, Any]) -> None:
        """Updates the keystore value (adding or removing) and reload.

        Raises:
            OpenSearchHttpError: If the reload fails.
        """
        ...

    @functools.cached_property
    @abstractmethod
    def list(self) -> List[str]:
        """Lists the keys available in opensearch's keystore."""
        ...

    def _clean_cache_if_needed(self):
        if self.list:
            del self.list

    @abstractmethod
    def reload_keystore(self) -> None:
        """Updates the keystore value (adding or removing) and reload.

        Raises:
            OpenSearchHttpError: If the reload fails.
        """
        ...


class OpenSearchKeystore(Keystore):
    """Manages keystore."""

    def __init__(self, charm):
        """Creates the keystore manager class."""
        super().__init__(charm)
        self._keystore = "keystore"
        self._keystore_path = f"{charm.opensearch.paths.conf}/opensearch.keystore"

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

    @functools.cached_property
    def list(self) -> List[str]:
        """Lists the keys available in opensearch's keystore."""
        if not os.path.exists(self._keystore_path):
            raise OpenSearchKeystoreNotReadyError()
        try:
            return self._opensearch.run_bin(self._keystore, "list").split("\n")
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    def _add(self, key: str, value: str):
        try:
            # Add newline to the end of the key, if missing
            value += "" if value.endswith("\n") else "\n"
            self._opensearch.run_bin(self._keystore, f"add --force {key}", stdin=value)

            self._clean_cache_if_needed()
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

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

    def reload_keystore(self) -> None:
        """Updates the keystore value (adding or removing) and reload.

        Raises:
            OpenSearchHttpError: If the reload fails.
        """
        response = self._opensearch.request("POST", "_nodes/reload_secure_settings")
        logger.debug(f"_update_keystore_and_reload: response received {response}")
