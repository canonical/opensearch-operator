# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the KNN and ML-Commons plugins for OpenSearch."""

import logging
from typing import List, Optional

from charms.opensearch.v0.opensearch_plugins import OpenSearchPlugin
from ops.framework import Object

logger = logging.getLogger(__name__)


# The unique Charmhub library identifier, never change it
LIBID = "71166db20ab244099ae966c8055db2df"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class OpenSearchPluginKnn(OpenSearchPlugin):
    """Implements the opensearch-knn plugin."""

    def __init__(self, name: str, charm: Object, relname: Optional[str] = None):
        super().__init__(name, charm, relname)
        self._depends_on = []

    def upgrade(self, uri: str) -> None:
        """Runs the upgrade process in this plugin."""
        raise NotImplementedError

    def is_enabled(self) -> bool:
        """Returns True if the plugin is enabled."""
        return (
            True
            if self.distro.config.load(self.CONFIG_YML).get("knn.plugin.enabled", "false")
            == "true"
            else False
        )

    def disable(self) -> bool:
        """Disables the plugin."""
        return self.configure(opensearch_yml={"knn.plugin.enabled": False})

    def enable(self) -> bool:
        """Enables the plugin."""
        return self.configure(opensearch_yml={"knn.plugin.enabled": True})

    @property
    def depends_on(self) -> List[str]:
        """Returns a list of plugins it depends on."""
        return self._depends_on


class OpenSearchPluginMLCommons(OpenSearchPlugin):
    """Implements the opensearch-ml-commons plugin."""

    def __init__(self, name: str, charm: Object, relname: Optional[str] = None):
        super().__init__(name, charm, relname)
        self._depends_on = []

    def upgrade(self, uri: str) -> None:
        """Runs the upgrade process in this plugin. No actions needed."""
        return

    def is_enabled(self) -> bool:
        """Returns True always, as this plugin cannot be disabled."""
        return True

    def enable(self) -> bool:
        """Enables the plugin."""
        return self.configure(
            opensearch_yml={
                "plugins.ml_commons.only_run_on_ml_node": True,
                "plugins.ml_commons.task_dispatch_policy": "round_robin",
                "plugins.ml_commons.max_ml_task_per_node": 20,
                "plugins.ml_commons.max_model_on_node": 100,
                "plugins.ml_commons.sync_up_job_interval_in_seconds": 3,
                "plugins.ml_commons.monitoring_request_count": 100,
                "plugins.ml_commons.max_register_model_tasks_per_node": 10,
                "plugins.ml_commons.allow_registering_model_via_url": False,
                "plugins.ml_commons.allow_registering_model_via_local_file": False,
                "plugins.ml_commons.trusted_url_regex": '"^(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]"',
                "plugins.ml_commons.ml_task_timeout_in_seconds": 600,
                "plugins.ml_commons.native_memory_threshold": 90,
                "plugins.ml_commons.allow_custom_deployment_plan": False,
                "plugins.ml_commons.model_auto_redeploy.enable": False,
                "plugins.ml_commons.model_auto_redeploy.lifetime_retry_times": 3,
                "plugins.ml_commons.model_auto_redeploy_success_ratio": 0.8,
                "plugins.ml_commons.enable_inhouse_python_model": False,
                "plugins.ml_commons.connector_access_control_enabled": True,
            }
        )

    def disable(self) -> bool:
        """Disables the plugin."""
        return False

    @property
    def depends_on(self) -> List[str]:
        """Returns a list of plugins it depends on."""
        return self._depends_on

    def install(self, uri: str, batch=True) -> bool:
        """Installs the plugin: ML Commons is a default plugin, no action needed."""
        return
