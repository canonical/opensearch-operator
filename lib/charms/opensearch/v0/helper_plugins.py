# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility functions for plugin secrets related operations."""
import json
import logging
from typing import Optional

# The unique Charmhub library identifier, never change it
LIBID = "f74617010c314bb7807475d9f4de6e09"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


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
