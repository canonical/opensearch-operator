# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility functions for plugin secrets related operations."""
import json
import logging
from typing import TYPE_CHECKING, Any, Optional

from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import ModelError, SecretNotFoundError

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

# The unique Charmhub library identifier, never change it
LIBID = "f74617010c314bb7807475d9f4de6e09"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


def store_plugin_secret(
    charm: "OpenSearchBaseCharm",
    content: dict[str, Any],
    label: str,
    relation_name: Optional[str] = None,
) -> None:
    """Creates/updates app-scoped plugin secret and stores id in peers data.

    Args:
        charm: charm instance
        content: dictionary of the secret payload
        label: label of the secret to store
        relation_name: name of the relation from which the secret content came
    """
    charm.secrets.put(Scope.APP, label, json.dumps(content))
    if not (secret_id := charm.secrets.get_secret_id(Scope.APP, label)):
        logger.error("Could not create secret with label: %s", label)
    charm.plugin_manager.put_plugin_config(
        Scope.APP, label=label, secret_id=secret_id, relation_name=relation_name
    )


def remove_plugin_secret(charm: "OpenSearchBaseCharm", label: str) -> None:
    """Deletes app-scoped plugin secret and removes id from peers data.

    Args:
        charm: charm instance
        label: label of the secret to remove
    """
    try:
        charm.secrets.delete(Scope.APP, label)
    except SecretNotFoundError:
        logger.error("Can't find secret '%s'", label)
    except ModelError as e:
        logger.error("Cannot delete secret %s: %s", label, e)
    charm.plugin_manager.remove_plugin_config(Scope.APP, label)


def decode_plugin_secret_content(content: dict, label: str) -> Optional[dict]:
    """Decodes JSON payload from plugin secret

    Args:
        content: dictionary of the secret content
        label: label of the secfet

    Returns:
        A decoded dictionary if successful, else None
    """
    if not (raw := content.get(label)):
        logger.warning("Key '%s' not found in secret content", label)
        return None

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error("Malformed JSON in secret %s: %s", label, e)
        return None
