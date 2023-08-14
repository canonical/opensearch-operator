# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility classes for app / unit data bag related operations."""

import json
import logging
from abc import ABC, abstractmethod
from ast import literal_eval
from typing import Dict, Optional, Union

from charms.opensearch.v0.constants_charm import Scope
from charms.opensearch.v0.constants_secrets import SecretData
from ops import JujuVersion, Secret, SecretNotFoundError
from overrides import override

# The unique Charmhub library identifier, never change it
LIBID = "e28df77e11504aef9a537b351fd4cf37"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


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


class SecretCache:
    """Internal helper class to objectify cached secrets."""

    def __init__(self):
        # Structure:
        # self.secrets = {
        #   "app": {
        #       "opensearch:app:admin-password": "bla"
        #   },
        #   "unit": {
        #       "opensearch:unit:0:certificates": {
        #           "ca-cert": "<certificate>",
        #           "cert": "<certificate>",
        #           "chain": "<certificate>"
        #   }
        # }
        self.secrets = {Scope.APP: {}, Scope.UNIT: {}}

    def get_meta(self, scope: Scope, label: str) -> Optional[Secret]:
        """Getting cached secret meta-information."""
        return self.secrets[scope].get(label, {}).get(SecretData.CACHED_META.val)

    def set_meta(self, scope: Scope, label: str, secret: Secret) -> None:
        """Setting cached secret meta-information."""
        self.secrets[scope].setdefault(label, {}).update({SecretData.CACHED_META.val: secret})

    def get_content(self, scope: Scope, label: str) -> Dict[str, str]:
        """Getting cached secret content."""
        return self.secrets[scope].get(label, {}).get(SecretData.CACHED_CONTENT.val)

    def set_content(self, scope: Scope, label: str, content: Union[str, dict]):
        """Setting cached secret content."""
        self.secrets[scope].setdefault(label, {}).update({SecretData.CACHED_CONTENT.val: content})

    def update(
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
            self.set_content(scope, label, content)

    def remove(self, scope: Scope, label: str) -> None:
        """Removing cached secret information."""
        if label in self.secrets[scope]:
            self.secrets[scope].pop(label)


class SecretsDataStore(RelationDataStore):
    """Class representing a secret store for a charm.

    For now, it is simply a base class for regular Relation data store
    """

    def __init__(self, charm, relation_name: str):
        super().__init__(charm, relation_name)
        self.cached_secrets = SecretCache()
        self._jujuversion = None

    @property
    def implements_secrets(self):
        """Property to cache resutls from a Juju call."""
        return JujuVersion.from_environ().has_secrets

    def label(self, scope: Scope, key: str) -> str:
        """Generated keys to be used within relation data to refer to secret IDs."""
        components = [self._charm.app.name, scope.val]
        if scope == Scope.UNIT:
            components.append(str(self._charm.unit_id))
        components.append(key)
        return SecretData.LABEL_SEPARATOR.val.join(components)

    def breakdown_label(self, label) -> Optional[Dict[str, str]]:
        """Return meaningful components resolved from a secret label."""
        components = label.split(SecretData.LABEL_SEPARATOR.val)

        unit_id = None
        key = None
        if len(components) == 3:
            key = components[2]
        elif len(components) == 4:
            try:
                unit_id = int(components[2])
            except ValueError:
                logging.error(
                    "Invalid label %s, length suggest unit secret yet no unit_id (int) was found",
                    label,
                )
                return
            key = components[3]
        else:
            logging.error("Invalid label %s", label)
            return

        return {
            "application_name": components[0],
            "scope": components[1],
            "unit_id": unit_id,
            "key": key,
        }

    @staticmethod
    def _safe_obj_data(indict: Dict) -> Dict:
        return {key: str(val) for key, val in indict.items() if val is not None}

    def _get_juju_secret(self, scope: Scope, key: str) -> Optional[Secret]:
        label = self.label(scope, key)

        cached_secret_meta = self.cached_secrets.get_meta(scope, label)
        if cached_secret_meta:
            return cached_secret_meta

        try:
            secret = self._charm.model.get_secret(label=label)
        except SecretNotFoundError:
            return None

        self.cached_secrets.set_meta(scope, label, secret)
        return secret

    def _get_juju_secret_content(self, scope: Scope, key: str) -> Optional[Dict]:
        cached_secret_content = self.cached_secrets.get_content(scope, self.label(scope, key))
        if cached_secret_content:
            return cached_secret_content

        secret = self._get_juju_secret(scope, key)
        if not secret:
            return None

        content = secret.get_content()
        self.cached_secrets.set_content(scope, self.label(scope, key), content=content)
        return content

    def _add_juju_secret(self, scope: Scope, key: str, value: Dict[str, str]) -> Optional[Secret]:
        safe_value = self._safe_obj_data(value)

        if not safe_value:
            return None

        scope_obj = None
        if scope == Scope.APP:
            scope_obj = self._charm.app
        if scope == Scope.UNIT:
            scope_obj = self._charm.unit

        try:
            secret = scope_obj.add_secret(safe_value, label=self.label(scope, key))
        except ValueError:
            logging.error("Secert %s:%s couldn't be added", str(scope.val), str(key))
            return None

        self.cached_secrets.update(scope, self.label(scope, key), secret, safe_value)
        return secret

    def _update_juju_secret(
        self, scope: Scope, key: str, value: Dict[str, str], merge: bool = False
    ) -> Optional[Secret]:
        # If the call below occurs for the 2nd time within the same flow,
        # it's hitting on the cache (i.e. cheap)
        secret = self._get_juju_secret(scope, key)

        content = {}
        if merge:
            content = self._get_juju_secret_content(scope, key)

        content.update(value)
        safe_content = self._safe_obj_data(content)

        if not safe_content:
            return self._remove_juju_secret(scope, key)

        try:
            secret.set_content(safe_content)
        except ValueError:
            logging.error("Secret %s:%s can't be updated", str(scope), str(key))
            return None

        self.cached_secrets.update(scope, self.label(scope, key), content=safe_content)
        return secret

    def _add_or_update_juju_secret(
        self, scope: Scope, key: str, value: Dict[str, str], merge: bool = False
    ):
        # Existing secret?
        if not self._get_juju_secret(scope, key):
            return self._add_juju_secret(scope, key, value)
        else:
            return self._update_juju_secret(scope, key, value, merge)

    def _remove_juju_secret(self, scope: Scope, key: str):
        secret = self._get_juju_secret(scope, key)
        if not secret:
            logging.warning(f"Secret {scope}:{key} can't be deleted as it doesn't exist")
            return None

        secret.remove_all_revisions()
        self.cached_secrets.remove(scope, self.label(scope, key))

    @override
    def has(self, scope: Scope, key: str):
        """Check if the said key is contained in the relation data."""
        if scope is None:
            raise ValueError("Scope undefined.")

        if not self.implements_secrets:
            return super().has(scope, key)

        return bool(self._get_juju_secret(scope, key))

    @override
    def get(
        self,
        scope: Scope,
        key: str,
        default: Optional[Union[int, float, str, bool]] = None,
        auto_casting: bool = True,
    ) -> Optional[Union[int, float, str, bool]]:
        """Getting a secret's value."""
        logging.debug(f"Getting secret {scope}:{key}")

        if not self.implements_secrets:
            return super().get(scope, key, default, auto_casting)

        content = self._get_juju_secret_content(scope, key)
        if not content:
            return default
        value = content.get(key)

        if not value:
            return None

        if not auto_casting:
            return value

        if not isinstance(value, dict):
            return self.cast(value)
        else:
            raise TypeError(f"Secret {scope}:{key} is to be retrieved with 'get_object()'")

    @override
    def get_object(self, scope: Scope, key: str) -> Optional[Dict[str, any]]:
        """Get dict object from the relation data store."""
        if not self.implements_secrets:
            return super().get_object(scope, key)

        return self._get_juju_secret_content(scope, key)

    @override
    def put(self, scope: Scope, key: str, value: Optional[Union[any]]) -> None:
        """Adding or updating a secret's value."""
        logging.debug(f"Putting secret {scope}:{key}")
        if not self.implements_secrets:
            return super().put(scope, key, value)

        self._add_or_update_juju_secret(scope, key, {key: value})

    @override
    def put_object(
        self, scope: Scope, key: str, value: Dict[str, any], merge: bool = False
    ) -> None:
        """Put a dict object into relation data store."""
        logging.debug(f"Putting secret object {scope}:{key}")
        if not self.implements_secrets:
            return super().put_object(scope, key, value, merge)

        self._add_or_update_juju_secret(scope, key, value, merge)

    @override
    def delete(self, scope: Scope, key: str) -> None:
        """Removing a secret."""
        logging.debug(f"Removing secret {scope}:{key}")

        if not self.implements_secrets:
            return super().delete(scope, key)

        self._remove_juju_secret(scope, key)

        logging.debug(f"Deleted secret {scope}:{key}")
