# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility classes for app / unit data bag related operations."""

import json
from abc import ABC, abstractmethod
from ast import literal_eval
from typing import Dict, Optional, Union

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_enums import BaseStrEnum
from overrides import override

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
    def all(self, scope: Scope) -> Dict[str, str]:
        """Get all content of a store."""
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
    def all(self, scope: Scope) -> Dict[str, str]:
        """Get all content of a store."""
        if scope is None:
            raise ValueError("Scope undefined.")

        return self._get_relation_data(scope)

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


class SecretsDataStore(RelationDataStore):
    """Class representing a secret store for a charm.

    For now, it is simply a base class for regular Relation data store
    """

    def get_unit_certificates(self) -> Dict[CertType, str]:
        """Retrieve the list of certificates for this unit."""
        certs = {}

        transport_secrets = self.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val)
        if transport_secrets and "cert" in transport_secrets:
            certs[CertType.UNIT_TRANSPORT] = transport_secrets["cert"]

        http_secrets = self.get_object(Scope.UNIT, CertType.UNIT_HTTP.val)
        if http_secrets and "cert" in http_secrets:
            certs[CertType.UNIT_HTTP] = http_secrets["cert"]

        if self._charm.unit.is_leader():
            admin_secrets = self.get_object(Scope.APP, CertType.APP_ADMIN.val)
            if admin_secrets and "cert" in admin_secrets:
                certs[CertType.APP_ADMIN] = admin_secrets["cert"]

        return certs
