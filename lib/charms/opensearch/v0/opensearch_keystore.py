# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
)
from ops import EventBase, EventSource, Object

# The unique Charmhub library identifier, never change it
LIBID = "de98efa151804b699d5d6128fa100807"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class ReloadKeystoreEvent(EventBase):
    """Event to signal that the keystore should be reloaded."""


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

    def reload(self) -> bool:
        """Reload the keystore."""
        self._create_if_needed()
        self._opensearch.run_bin("keystore", "upgrade")

        if not self._opensearch.is_started():
            # service not running, settings will be picked up at startup
            logger.debug("Opensearch not running. Keystore settings will be loaded at start time.")
            return True

        try:
            response = self._opensearch.request("POST", "_nodes/reload_secure_settings")
        except OpenSearchHttpError as e:
            logger.error("Could not reload secure settings: %s", e)
            return False

        success = response.get("_nodes", {}).get("failed", -1) == 0
        logger.debug("keystore reloaded: %s", success)
        return success


class OpenSearchKeystoreEvents(Object):
    """Keystore events."""

    reload_event = EventSource(ReloadKeystoreEvent)

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ) -> None:
        """Initialize keystore events."""
        super().__init__(charm, key="opensearch_keystore_events")
        self.charm = charm

        self.framework.observe(self.reload_event, self._on_reload)

    def _on_reload(self, event: ReloadKeystoreEvent) -> None:
        """Handle keystore reload event."""
        if not self.charm.keystore_manager.reload():
            logger.error("Keystore reload failed.")
            event.defer()
