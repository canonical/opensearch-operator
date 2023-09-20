# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the KNN and ML-Commons plugins for OpenSearch."""

import logging
from typing import Any, Dict, List

from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchPlugin,
    OpenSearchPluginConfig,
)

logger = logging.getLogger(__name__)


# The unique Charmhub library identifier, never change it
LIBID = "71166db20ab244099ae966c8055db2df"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class OpenSearchKnn(OpenSearchPlugin):
    """Implements the opensearch-knn plugin."""

    def __init__(self, plugins_path: str, extra_config: Dict[str, Any] = None):
        super().__init__(plugins_path, extra_config)

    def config(self) -> OpenSearchPluginConfig:
        """Returns a dict containing all the configuration needed to be applied in the form."""
        return OpenSearchPluginConfig(
            config_entries_to_add={"knn.plugin.enabled": "True"},
            config_entries_to_del={"knn.plugin.enabled": "False"},
        )

    def disable(self) -> OpenSearchPluginConfig:
        """Returns a tuple containing different config changes."""
        return OpenSearchPluginConfig(
            config_entries_to_add={"knn.plugin.enabled": "False"},
            config_entries_to_del={"knn.plugin.enabled": "True"},
        )

    @property
    def name(self) -> str:
        """Returns the name of the plugin."""
        return "opensearch-knn"

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of plugin name dependencies."""
        return []
