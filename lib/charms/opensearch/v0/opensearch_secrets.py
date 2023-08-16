# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class we manage certificates relation.

This class handles certificate request and renewal through
the interaction with the TLS Certificates Operator.

This library needs https://charmhub.io/tls-certificates-interface/libraries/tls_certificates
library is imported to work.

It requires a charm that extends OpenSearchBaseCharm as it refers internal objects of that class.
— update_config: to disable TLS when relation with the TLS Certificates Operator is broken.
"""

import logging
import time
from typing import Dict, Optional, Union

from charms.opensearch.v0.constants_charm import Scope
from charms.opensearch.v0.constants_secrets import SecretData
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.opensearch_internal_data import RelationDataStore, SecretCache
from ops import JujuVersion, Secret, SecretNotFoundError
from ops.charm import ActionEvent
from ops.framework import Object
from overrides import override

# The unique Charmhub library identifier, never change it
LIBID = "8bcf275287ad486db5f25a1dbb26f920"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OpenSearchSecrets(Object, RelationDataStore):
    """In a long term this should inherit from DataStore abstract interface"""

    def __init__(self, charm, peer_relation: str):
        Object.__init__(self, charm, peer_relation)
        SecretsDataStore.__init__(self, charm, peer_relation)

        self.charm = charm
        self.peer_relation = peer_relation

        self.cached_secrets = SecretCache()
        self._jujuversion = None

        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_secret_changed(self, event: ActionEvent):
        """Refresh secret and re-run corresponding actions if needed."""
        if not event.secret.label:
            logger.info("Secret %s has no label, ignoring it", event.secret.id)

        label_parts = self.breakdown_label(event.secret.label)
        if (
            label_parts["application_name"] == self.charm.app.name
            and label_parts["scope"] == Scope.APP
            and label_parts["key"] == CertType.APP_ADMIN.val
        ):
            scope = Scope.APP
        else:
            logger.info("Secret %s was not relevant for us.", event.secret.label)
            return

        logger.debug("Secret change for %s, %s", scope, label_parts["key"])

        if not self.charm.unit.is_leader():
            self.charm.store_tls_resources(CertType.APP_ADMIN, event.secret.get_content())

    @property
    def implements_secrets(self):
        """Property to cache resutls from a Juju call."""
        return JujuVersion.from_environ().has_secrets

    @staticmethod
    def elapsed(f: callable, *args, **kwargs):
        """Temporary time measurement method."""
        start = time.time()
        result = f(*args, **kwargs)
        end = time.time()
        logging.info(f"Secret operation {f} takes {end-start}")
        return result

    def label(self, scope: Scope, key: str) -> str:
        """Generated keys to be used within relation data to refer to secret IDs."""
        components = [self.charm.app.name, scope.val]
        if scope == Scope.UNIT:
            components.append(str(self.charm.unit_id))
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
            unit_id = int(components[2])
            key = components[3]

        if components[1] == Scope.APP.val:
            scope = Scope.APP
        elif components[1] == Scope.UNIT.val:
            scope = Scope.UNIT

        return {
            "application_name": components[0],
            "scope": scope,
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
            secret = self.elapsed(self.charm.model.get_secret, label=label)
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

        content = self.elapsed(secret.get_content)
        self.cached_secrets.set_content(scope, self.label(scope, key), content=content)
        return content

    def _add_juju_secret(self, scope: Scope, key: str, value: Dict[str, str]) -> Optional[Secret]:
        safe_value = self._safe_obj_data(value)

        if not safe_value:
            return None

        scope_obj = None
        if scope == Scope.APP:
            scope_obj = self.charm.app
        if scope == Scope.UNIT:
            scope_obj = self.charm.unit

        try:
            secret = self.elapsed(scope_obj.add_secret, safe_value, label=self.label(scope, key))
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
            self.elapsed(secret.set_content, safe_content)
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

        self.elapsed(secret.remove_all_revisions)
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
