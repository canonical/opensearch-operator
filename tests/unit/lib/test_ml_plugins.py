# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
import unittest
from unittest.mock import MagicMock, PropertyMock, patch

import charms
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_plugins import OpenSearchKnn, PluginState
from ops.testing import Harness

from charm import OpenSearchOperatorCharm

RETURN_LIST_PLUGINS = """opensearch-alerting
opensearch-anomaly-detection
opensearch-asynchronous-search
opensearch-cross-cluster-replication
opensearch-geospatial
opensearch-index-management
opensearch-job-scheduler
opensearch-knn
opensearch-ml
opensearch-notifications
opensearch-notifications-core
opensearch-observability
opensearch-performance-analyzer
opensearch-reports-scheduler
opensearch-security
opensearch-sql
prometheus-exporter
"""


class TestOpenSearchKNN(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"

    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm
        self.charm.opensearch.paths.plugins = "tests/unit/resources"
        self.plugin_manager = self.charm.plugin_manager
        self.plugin_manager._plugins_path = self.charm.opensearch.paths.plugins
        # Override the ConfigExposedPlugins and ensure one single plugin exists
        charms.opensearch.v0.opensearch_plugin_manager.ConfigExposedPlugins = {
            "opensearch-knn": {
                "class": OpenSearchKnn,
                "config": "plugin_opensearch_knn",
                "relation": None,
            }
        }
        self.charm.opensearch.is_started = MagicMock(return_value=True)
        self.charm.health.apply = MagicMock(return_value=HealthColors.GREEN)
        self.plugin_manager._is_cluster_ready = MagicMock(return_value=True)
        charms.opensearch.v0.helper_cluster.ClusterTopology.get_cluster_settings = MagicMock(
            return_value={}
        )

    @patch(f"{BASE_LIB_PATH}.opensearch_distro.OpenSearchDistribution.is_node_up")
    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch(
        "charms.opensearch.v0.opensearch_locking.OpenSearchNodeLock.acquired",
        new_callable=PropertyMock,
    )
    @patch(
        "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.version",
        new_callable=PropertyMock,
    )
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._is_enabled")
    @patch("charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager.status")
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_started")
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
    def test_disable_via_config_change(
        self,
        _,
        __,
        mock_is_started,
        mock_status,
        mock_is_enabled,
        mock_version,
        mock_lock_acquired,
        ___,
        mock_is_node_up,
    ) -> None:
        """Tests entire config_changed event with KNN plugin."""
        mock_status.return_value = PluginState.ENABLED
        mock_is_enabled.return_value = False
        mock_is_started.return_value = True
        mock_version.return_value = "2.9.0"
        self.plugin_manager._keystore.add = MagicMock()
        self.plugin_manager._keystore.delete = MagicMock()
        self.plugin_manager._opensearch_config.delete_plugin = MagicMock()
        self.plugin_manager._opensearch_config.add_plugin = MagicMock()
        self.charm.status = MagicMock()
        mock_is_node_up.return_value = True
        self.charm._get_nodes = MagicMock(return_value=[1])
        self.charm.planned_units = MagicMock(return_value=1)
        mock_lock_acquired.return_value = False

        self.harness.update_config({"plugin_opensearch_knn": False})
        mock_lock_acquired.assert_called_once()
        self.plugin_manager._opensearch_config.add_plugin.assert_called_once_with(
            {"knn.plugin.enabled": "false"}
        )
