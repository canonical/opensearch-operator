# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility functions for plugin secrets related operations."""
import json
import logging
from typing import TYPE_CHECKING, Optional

from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import ModelError, SecretNotFoundError

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


def store_plugin_secret(
    charm, content: dict, label: str, relation_name: str | None = None
) -> str | None:
    """
    Leader-only: upsert an APP-scoped secret for label, keeping exactly one payload level,
    then persist the secret_id in plugin_manager.
    """
    if not charm.unit.is_leader():
        return None

    try:
        app_label = charm.secrets.label(Scope.APP, label)  # "<app>:app:<label>"
        if "payload" in content:
            inner = content["payload"]
            packed = {"payload": inner if isinstance(inner, str) else json.dumps(inner)}
        else:
            packed = {"payload": json.dumps(content)}

        secret_id = charm.secrets.get_secret_id(Scope.APP, label)
        if secret_id:
            # update existing secret content
            sec = charm.model.get_secret(id=secret_id)
            sec.set_content(packed)
        else:
            # create new secret with label
            sec = charm.app.add_secret(content=packed, label=app_label)
            secret_id = sec.id

        if not secret_id:
            logger.error("[plugins] no secret id obtained for %s", app_label)
            return None

        charm.plugin_manager.put_plugin_config(
            Scope.APP, label=label, secret_id=secret_id, relation_name=relation_name
        )
        return secret_id

    except Exception as e:
        logger.error("[plugins] store_plugin_secret(%s) failed: %s", label, e)
        return None


def remove_plugin_secret(charm: "OpenSearchBaseCharm", label: str) -> None:
    """Deletes app-scoped plugin secret and removes id from peers data."""
    try:
        charm.secrets.delete(Scope.APP, label)
    except SecretNotFoundError:
        logger.debug("Can't find secret '%s'", label)
    except ModelError as e:
        logger.debug("Cannot delete secret %s: %s", label, e)
    charm.plugin_manager.remove_plugin_config(Scope.APP, label)


def decode_plugin_secret_content(content: dict, label: str) -> Optional[dict]:
    """Decodes JSON payload from plugin secret"""
    if not (raw := content.get(label)):
        logger.warning("Key '%s' not found in secret content", label)
        return None

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.error("Malformed JSON in secret %s", label)
        return None
