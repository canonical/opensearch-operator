# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Utility functions for charms COS operations."""


import json
import logging
from typing import TYPE_CHECKING

from data_platform_helpers.version_check import get_charm_revision

# The unique Charmhub library identifier, never change it
LIBID = "98222ad783074ec6b098d4014b853119"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm


def update_grafana_dashboards_title(charm: "OpenSearchBaseCharm") -> None:
    """Update the title of the Grafana dashboard file to include the charm revision."""
    revision = get_charm_revision(charm.model.unit)
    dashboard_path = charm.charm_dir / "src/grafana_dashboards/opensearch.json"

    with open(dashboard_path, "r") as file:
        dashboard = json.load(file)

    old_title = dashboard.get("title", "Charmed OpenSearch")
    title_prefix = old_title.split(" - Rev")[0]
    new_title = f"{old_title} - Rev {revision}"
    dashboard["title"] = f"{title_prefix} - Rev {revision}"

    logger.info(
        "Changing the title of dashboard %s from %s to %s",
        dashboard_path.name,
        old_title,
        new_title,
    )

    with open(dashboard_path, "w") as file:
        json.dump(dashboard, file, indent=4)
