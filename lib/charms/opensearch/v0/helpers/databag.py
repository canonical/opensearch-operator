# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility classes for app / unit data bag related operations."""

import json
from enum import Enum
from typing import Dict, Optional


class Scope(Enum):
    """Peer relations scope."""

    APP = "app"
    UNIT = "unit"

    def __str__(self):
        """String representation of enum value."""
        return self.value


class SecretStore:
    """Class representing a secret store for a charm.

    Requires the following 2 properties on the charm:
      - app_peers_data
      - unit_peers_data
    """

    def __init__(self, charm):
        self._charm = charm

    def put(self, scope: Scope, key: str, value: Optional[str]) -> None:
        """Put string secret into the secret storage."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._charm.unit_peers_data
        if scope == Scope.APP:
            data = self._charm.app_peers_data

        self._put_or_delete(data, key, value)

    def put_object(
        self, scope: Scope, key: str, value: Dict[str, any], merge: bool = False
    ) -> None:
        """Put dict / json object secret into the secret storage."""
        if merge:
            stored = self.get_object(scope, key)

            if stored is not None:
                stored.update(value)
                value = stored

        payload_str = None
        if value is not None:
            payload_str = json.dumps(value)

        self.put(scope, key, payload_str)

    def get(self, scope: Scope, key: str) -> Optional[str]:
        """Get string secret from the secret storage."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._charm.unit_peers_data
        if scope == Scope.APP:
            data = self._charm.app_peers_data

        return data.get(key, None)

    def get_object(self, scope: Scope, key: str) -> Optional[Dict[str, any]]:
        """Get dict / json object secret from the secret storage."""
        data = self.get(scope, key)
        if data is None:
            return None

        return json.loads(data)

    def delete(self, scope: Scope, key: str):
        """Delete secret from the secret storage."""
        self.put(scope, key, None)

    @staticmethod
    def _put_or_delete(peers_data: Dict[str, str], key: str, value: Optional[str]):
        """Put data into the secret storage or delete if value is None."""
        if value is None:
            del peers_data[key]
            return

        peers_data.update({key: value})
