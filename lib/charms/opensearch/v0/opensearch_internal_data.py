# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility classes for app / unit data bag related operations."""

import json
import logging
from abc import ABC, abstractmethod
from ast import literal_eval
from typing import Dict, Optional, Union

from charms.opensearch.v0.helper_enums import BaseStrEnum
from ops import Secret
from overrides import override

# The unique Charmhub library identifier, never change it
LIBID = "e28df77e11504aef9a537b351fd4cf37"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class Scope(BaseStrEnum):
    """Peer relations scope."""

    APP = "app"
    UNIT = "unit"


class DataStore(ABC):
    """Class representing a data store used in the OPs code of the charm."""

    def __init__(self, charm):
        self._charm = charm

    @abstractmethod
    def put(self, scope: Scope, key: str, value: Optional[any]) -> None:
        """Put string into the data store."""
        pass

    @abstractmethod
    def put_object(
        self, scope: Scope, key: str, value: Dict[str, any], merge: bool = False
    ) -> None:
        """Put object into the data store."""
        pass

    @abstractmethod
    def has(self, scope: Scope, key: str):
        """Check if the said key is contained in the store."""
        pass

    @abstractmethod
    def get(
        self, scope: Scope, key: str, default: Optional[Union[int, float, str, bool]] = None
    ) -> Optional[Union[int, float, str, bool]]:
        """Get string from the data store."""
        pass

    @abstractmethod
    def get_object(self, scope: Scope, key: str) -> Optional[Dict[str, any]]:
        """Get dict / json object from the data store."""
        pass

    @abstractmethod
    def delete(self, scope: Scope, key: str):
        """Delete object from the data store."""
        pass

    @staticmethod
    def cast(str_val: str) -> Union[bool, int, float, str]:
        """Cast a string to the corresponding primitive type."""
        try:
            typed_val = literal_eval(str_val.capitalize())
            if type(typed_val) not in {bool, int, float, str}:
                return str_val

            return typed_val
        except (ValueError, SyntaxError):
            return str_val

    @staticmethod
    def put_or_delete(data: Dict[str, str], key: str, value: Optional[str]):
        """Put data into the key/val data store or delete if value is None."""
        if value is None:
            del data[key]
            return

        data.update({key: str(value)})


class RelationDataStore(DataStore):
    """Class representing a relation data store for a charm."""

    def __init__(self, charm, relation_name: str):
        super(RelationDataStore, self).__init__(charm)
        self.relation_name = relation_name

    @override
    def put(self, scope: Scope, key: str, value: Optional[Union[any]]) -> None:
        """Put string into the relation data store."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._get_relation_data(scope)

        self.put_or_delete(data, key, value)

    @override
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
            payload_str = json.dumps(value, default=vars)

        self.put(scope, key, payload_str)

    @override
    def has(self, scope: Scope, key: str):
        """Check if the said key is contained in the relation data."""
        if scope is None:
            raise ValueError("Scope undefined.")

        return key in self._get_relation_data(scope)

    @override
    def get(
        self,
        scope: Scope,
        key: str,
        default: Optional[Union[int, float, str, bool]] = None,
        auto_casting: bool = True,
    ) -> Optional[Union[int, float, str, bool]]:
        """Get string from the relation data store."""
        if scope is None:
            raise ValueError("Scope undefined.")

        data = self._get_relation_data(scope)

        value = data.get(key)
        if value is None:
            return default

        if not auto_casting:
            return value

        return self.cast(value)

    @override
    def get_object(self, scope: Scope, key: str) -> Optional[Dict[str, any]]:
        """Get dict / json object from the relation data store."""
        data = self.get(scope, key)
        if data is None:
            return None

        return json.loads(data)

    @override
    def delete(self, scope: Scope, key: str):
        """Delete object from the relation data store."""
        self.put(scope, key, None)

    def _get_relation_data(self, scope: Scope) -> Dict[str, str]:
        """Relation data object."""
        relation = self._charm.model.get_relation(self.relation_name)
        if relation is None:
            return {}

        relation_scope = self._charm.app if scope == Scope.APP else self._charm.unit

        return relation.data[relation_scope]


class SecretCache:
    """Internal helper class locally cache secrets.

    The data structure is precisely re-using/simulating as in the actual Secret Storage
    """

    CACHED_META = "meta"
    CACHED_CONTENT = "content"

    def __init__(self):
        # Structure:
        # NOTE: "objects" (i.e. dict-s) and scalar values are handled in a unified way
        # precisely as done for the Secret objects themselves.
        #
        # self.secrets = {
        #   "app": {
        #       "opensearch:app:admin-password": {
        #           "meta": <Secret instance>,
        #           "content": {
        #               "opensearch:app:admin-password": "bla"
        #           }
        #       }
        #   },
        #   "unit": {
        #       "opensearch:unit:0:certificates": {
        #           "meta": <Secret instance>,
        #           "content": {
        #               "ca-cert": "<certificate>",
        #               "cert": "<certificate>",
        #               "chain": "<certificate>"
        #           }
        #       }
        #   }
        # }
        self.secrets = {Scope.APP: {}, Scope.UNIT: {}}

    def get_meta(self, scope: Scope, label: str) -> Optional[Secret]:
        """Getting cached secret meta-information."""
        return self.secrets[scope].get(label, {}).get(self.CACHED_META)

    def set_meta(self, scope: Scope, label: str, secret: Secret) -> None:
        """Setting cached secret meta-information."""
        self.secrets[scope].setdefault(label, {}).update({self.CACHED_META: secret})

    def get_content(self, scope: Scope, label: str) -> Dict[str, str]:
        """Getting cached secret content."""
        return self.secrets[scope].get(label, {}).get(self.CACHED_CONTENT)

    def put_content(self, scope: Scope, label: str, content: Union[str, Dict[str, str]]):
        """Setting cached secret content."""
        self.secrets[scope].setdefault(label, {}).update({self.CACHED_CONTENT: content})

    def put(
        self,
        scope: Scope,
        label: str,
        secret: Optional[Secret] = None,
        content: Optional[Union[str, Dict[str, str]]] = None,
    ) -> None:
        """Updating cached secret information."""
        if secret:
            self.set_meta(scope, label, secret)
        if content:
            self.put_content(scope, label, content)

    def delete(self, scope: Scope, label: str) -> None:
        """Removing cached secret information."""
        self.secrets[scope].pop(label, None)
