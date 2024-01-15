# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""This class is to handle Juju3 Secrets.

The module implements the event handler responsible for Juju3 secrets-related
events (such as secret-changed or secret-remove).

The OpenSearchSecrets class implements the DataStorage interface,
being responsible both for event handling and managing sensitive
information for the Opensearch charm.
"""

import logging
from typing import Dict, Optional, Union

from charms.opensearch.v0.constants_secrets import PW_POSTFIX
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.opensearch_exceptions import OpenSearchSecretInsertionError
from charms.opensearch.v0.opensearch_internal_data import (
    RelationDataStore,
    Scope,
    SecretCache,
)
from ops import JujuVersion, Secret, SecretNotFoundError, model
from ops.charm import SecretChangedEvent
from ops.framework import Object
from overrides import override

# The unique Charmhub library identifier, never change it
LIBID = "d2bcf5b34e064adf9e27d8fbff36bc55"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class SecretUpdateFailedError(Exception):
    """The exception to be thrown when secret-changed fails to update its secret."""

    pass


class OpenSearchSecrets(Object, RelationDataStore):
    """Encapsulating Juju3 secrets handling."""

    LABEL_SEPARATOR = ":"

    def __init__(self, charm, peer_relation: str, secrets_to_cb: Dict[str, any] = {}):
        Object.__init__(self, charm, peer_relation)
        RelationDataStore.__init__(self, charm, peer_relation)

        self.cached_secrets = SecretCache()
        self.secrets_to_cb = secrets_to_cb

        self.framework.observe(self._charm.on.secret_changed, self._on_secret_changed)

    def _update_secret_value(self, event: SecretChangedEvent):
        """Updates the secret value following newer 3.1.7 behavior."""
        secret = event.secret
        secret.get_content(refresh=True)

    def _on_secret_changed(self, event: SecretChangedEvent):
        """Refresh secret and re-run corresponding actions if needed."""
        self._update_secret_value(event)

        if not event.secret.label:
            logger.info("Secret %s has no label, ignoring it.", event.secret.id)
            return

        try:
            label_parts = self.breakdown_label(event.secret.label)
        except ValueError:
            logging.info(f"Label {event.secret.label} was meaningless for us, returning")
            return

        if (
            label_parts["application_name"] != self._charm.app.name
            or label_parts["scope"] != Scope.APP
            or label_parts["key"] != CertType.APP_ADMIN.val
        ):
            logger.info("Secret %s was not relevant for us.", event.secret.label)
            return

        logger.debug("Secret change for %s", str(label_parts["key"]))
        if not self._charm.unit.is_leader():
            self._charm.store_tls_resources(CertType.APP_ADMIN, event.secret.get_content())

    @property
    def implements_secrets(self):
        """Property to cache results from a Juju call."""
        return JujuVersion.from_environ().has_secrets

    def password_key(self, username: str) -> str:
        """Unified key to store password secrets specific to a user."""
        return f"{username}-{PW_POSTFIX}"

    def label(self, scope: Scope, key: str) -> str:
        """Generated keys to be used within relation data to refer to secret IDs."""
        components = [self._charm.app.name, scope.val]
        if scope == Scope.UNIT:
            components.append(str(self._charm.unit_id))
        components.append(key)
        return self.LABEL_SEPARATOR.join(components)

    def breakdown_label(self, label: str) -> Dict[str, str]:
        """Return meaningful components resolved from a secret label."""
        components = label.split(self.LABEL_SEPARATOR)
        if len(components) < 3 or len(components) > 4:
            raise ValueError("Invalid label %s", label)

        scope = Scope[components[1].upper()]

        if scope == Scope.APP:
            key = components[2]
            unit_id = None
        else:
            key = components[3]
            unit_id = int(components[2])

        return {
            "application_name": components[0],
            "scope": scope,
            "unit_id": unit_id,
            "key": key,
        }

    @staticmethod
    def _safe_obj_data(indict: Dict) -> Dict[str, any]:
        return {
            key: str(val) for key, val in indict.items() if val is not None and str(val).strip()
        }

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

    def _get_juju_secret_content(self, scope: Scope, key: str) -> Optional[Dict[str, str]]:
        cached_secret_content = self.cached_secrets.get_content(scope, self.label(scope, key))
        if cached_secret_content:
            return cached_secret_content

        secret = self._get_juju_secret(scope, key)
        if not secret:
            return None

        content = secret.get_content()
        self.cached_secrets.put_content(scope, self.label(scope, key), content=content)
        return content

    def _add_juju_secret(self, scope: Scope, key: str, value: Dict[str, str]) -> Optional[Secret]:
        safe_value = self._safe_obj_data(value)

        if not safe_value:
            return None

        scope_obj = self._charm.app if scope == Scope.APP else self._charm.unit

        label = self.label(scope, key)
        try:
            secret = scope_obj.add_secret(safe_value, label=label)
        except ValueError as e:
            logging.error("Secret %s:%s couldn't be added", str(scope.val), str(key))
            raise OpenSearchSecretInsertionError(e)

        self.cached_secrets.put(scope, label, secret, safe_value)

        # Keeping a reference of the secret's ID just for sure.
        # May come handy for internal Observer Juju relation.
        self._charm.peers_data.put(scope, label, secret.id)

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
        except ValueError as e:
            logging.error("Secret %s:%s couldn't be updated", str(scope.val), str(key))
            raise OpenSearchSecretInsertionError(e)

        self.cached_secrets.put(scope, self.label(scope, key), content=safe_content)
        return secret

    def _add_or_update_juju_secret(
        self, scope: Scope, key: str, value: Dict[str, str], merge: bool = False
    ):
        # Existing secret?
        if not self._get_juju_secret(scope, key):
            return self._add_juju_secret(scope, key, value)
        return self._update_juju_secret(scope, key, value, merge)

    def _remove_juju_secret(self, scope: Scope, key: str):
        secret = self._get_juju_secret(scope, key)
        if not secret:
            logging.warning(f"Secret {scope}:{key} can't be deleted as it doesn't exist")
            return None

        secret.remove_all_revisions()
        self.cached_secrets.delete(scope, self.label(scope, key))

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
