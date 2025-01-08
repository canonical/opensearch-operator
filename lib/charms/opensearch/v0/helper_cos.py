# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Utility functions for charms COS operations."""


import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from data_platform_helpers.version_check import get_charm_revision

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm


def update_grafana_dashboards_titles(charm: "OpenSearchBaseCharm") -> None:
    """Update the titles in the specified directory to include the charm revision."""
    revision = get_charm_revision(charm.model.unit)
    path = charm.charm_dir / "src/grafana_dashboards"

    for dashboard_path in path.iterdir():
        if dashboard_path.is_file() and dashboard_path.suffix == ".json":
            try:
                _update_dashboard_title(revision, dashboard_path)
            except (json.JSONDecodeError, IOError) as e:
                logger.error("Failed to process %s: %s", dashboard_path.name, str(e))
        else:
            logger.warning("%s is not a valid JSON file", dashboard_path.name)


def _update_dashboard_title(revision: str, dashboard_path: Path) -> None:
    """Update the title of a Grafana dashboard file to include the charm revision."""
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
