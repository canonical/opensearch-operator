# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility classes for app / unit data bag related operations."""

import json
from typing import Dict, Optional

from charms.opensearch.v0.helper_enums import BaseStrEnum

# The unique Charmhub library identifier, never change it
LIBID = "e28df77e11504aef9a537b351fd4cf37"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class Scope(BaseStrEnum):
    """Peer relations scope."""

    APP = "app"
    UNIT = "unit"


class Store:
    """Class representing a relation data store for a charm.

    Requires the following 2 properties on the charm:
      - app_peers_data
      - unit_peers_data
    """

    def __init__(self, charm):
        self._charm = charm

    def put(self, scope: Scope, key: str, value: Optional[str]) -> None:
        """Put object into the relation data store."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._charm.unit_peers_data
        if scope == Scope.APP:
            data = self._charm.app_peers_data

        self.put_or_delete(data, key, value)

    def put_object(
        self, scope: Scope, key: str, value: Dict[str, any], merge: bool = False
    ) -> None:
        """Put dict / json object into relation data store."""
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
        """Get string from the relation data store."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._charm.unit_peers_data
        if scope == Scope.APP:
            data = self._charm.app_peers_data

        return data.get(key, None)

    def get_object(self, scope: Scope, key: str) -> Optional[Dict[str, any]]:
        """Get dict / json object from the relation data store."""
        data = self.get(scope, key)
        if data is None:
            return None

        return json.loads(data)

    def delete(self, scope: Scope, key: str):
        """Delete object from the relation data store."""
        self.put(scope, key, None)

    @staticmethod
    def put_or_delete(peers_data: Dict[str, str], key: str, value: Optional[str]):
        """Put data into the relation data store or delete if value is None."""
        if value is None:
            del peers_data[key]
            return

        peers_data.update({key: value})


class SecretStore(Store):
    """Class representing a secret store for a charm.

    For now, it is simply a base class for regular Relation data store
    """

    pass
