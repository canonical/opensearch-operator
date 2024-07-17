# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch_plugins library."""
import unittest
from unittest.mock import MagicMock, PropertyMock, patch

import charms
from charms.opensearch.v0.models import App, Node
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_plugins import OpenSearchKnn
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

    @patch(f"{BASE_LIB_PATH}.opensearch_plugin_manager.OpenSearchPluginManager.is_ready_for_api")
    @patch(
        f"{BASE_LIB_PATH}.opensearch_plugins.OpenSearchKnn.version",
        new_callable=PropertyMock,
    )
    @patch(f"{BASE_LIB_PATH}.opensearch_plugin_manager.OpenSearchPluginManager._is_installed")
    @patch(f"{BASE_LIB_PATH}.opensearch_config.OpenSearchConfig.update_host_if_needed")
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
    @patch(
        "charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._user_requested_to_enable"
    )
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_started")
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
    def test_disable_via_config_change_node_up_but_api_unreachable(
        self,
        _,
        __,
        mock_is_started,
        mock_user_requested,
        mock_is_enabled,
        mock_version,
        mock_lock_acquired,
        ___,
        mock_is_node_up,
        mock_update_host_if_needed,
        ____,
        mock_plugin_version,
        mock_is_ready_for_api,
    ) -> None:
        """Tests entire config_changed event with KNN plugin."""
        mock_is_enabled.return_value = True
        mock_user_requested.return_value = False

        mock_is_ready_for_api.return_value = False
        mock_update_host_if_needed.return_value = False
        mock_is_started.return_value = True
        mock_version.return_value = "2.9.0"
        mock_plugin_version.return_value = "2.9.0"
        self.plugin_manager._keystore.update = MagicMock()
        self.plugin_manager._opensearch_config.update_plugin = MagicMock()
        self.charm.status = MagicMock()
        mock_is_node_up.return_value = True
        self.charm._get_nodes = MagicMock(
            return_value=[
                Node(
                    name=f"{self.charm.app.name}-0",
                    roles=["cluster_manager"],
                    ip="1.1.1.1",
                    app=App(model_uuid="model-uuid", name=self.charm.app.name),
                    unit_number=0,
                ),
            ]
        )
        self.charm._get_nodes = MagicMock(return_value=[1])
        self.charm.planned_units = MagicMock(return_value=1)
        self.charm._restart_opensearch_event = MagicMock()

        self.harness.update_config({"plugin_opensearch_knn": False})

        # in this case, without API available but the node is set as up
        # we then need to restart the service
        self.charm._restart_opensearch_event.emit.assert_called_once()
        self.plugin_manager._opensearch_config.update_plugin.assert_called_once_with(
            {"knn.plugin.enabled": None}
        )

    @patch(f"{BASE_LIB_PATH}.opensearch_distro.OpenSearchDistribution.request")
    @patch(
        f"{BASE_LIB_PATH}.opensearch_plugin_manager.OpenSearchPluginManager.cluster_config",
        new_callable=PropertyMock,
    )
    @patch(f"{BASE_LIB_PATH}.opensearch_plugin_manager.OpenSearchPluginManager.is_ready_for_api")
    @patch(
        f"{BASE_LIB_PATH}.opensearch_plugins.OpenSearchKnn.version",
        new_callable=PropertyMock,
    )
    @patch(f"{BASE_LIB_PATH}.opensearch_plugin_manager.OpenSearchPluginManager._is_installed")
    @patch(f"{BASE_LIB_PATH}.opensearch_config.OpenSearchConfig.update_host_if_needed")
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
    @patch(
        "charms.opensearch.v0.opensearch_plugin_manager.OpenSearchPluginManager._user_requested_to_enable"
    )
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_started")
    @patch("charms.opensearch.v0.opensearch_config.OpenSearchConfig.load_node")
    @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
    def test_disable_via_config_change_node_up_and_api_reachable(
        self,
        _,
        __,
        mock_is_started,
        mock_user_requested,
        mock_is_enabled,
        mock_version,
        mock_lock_acquired,
        ___,
        mock_is_node_up,
        mock_update_host_if_needed,
        ____,
        mock_plugin_version,
        mock_is_ready_for_api,
        mock_cluster_config,
        mock_api_request,
    ) -> None:
        """Tests entire config_changed event with KNN plugin."""
        mock_is_enabled.return_value = True
        mock_user_requested.return_value = False

        mock_is_ready_for_api.return_value = True
        mock_cluster_config.return_value = {
            "knn.plugin.enabled": "true",
        }
        mock_cluster_config.__delete__ = MagicMock()

        mock_update_host_if_needed.return_value = False
        mock_is_started.return_value = True
        mock_version.return_value = "2.9.0"
        mock_plugin_version.return_value = "2.9.0"
        self.plugin_manager._keystore.update = MagicMock()
        self.plugin_manager._opensearch_config.update_plugin = MagicMock()
        self.charm.status = MagicMock()
        mock_is_node_up.return_value = True
        self.charm._get_nodes = MagicMock(
            return_value=[
                Node(
                    name=f"{self.charm.app.name}-0",
                    roles=["cluster_manager"],
                    ip="1.1.1.1",
                    app=App(model_uuid="model-uuid", name=self.charm.app.name),
                    unit_number=0,
                ),
            ]
        )
        self.charm._get_nodes = MagicMock(return_value=[1])
        self.charm.planned_units = MagicMock(return_value=1)
        self.charm._restart_opensearch_event = MagicMock()

        self.harness.update_config({"plugin_opensearch_knn": False})
        self.charm._restart_opensearch_event.emit.assert_not_called()
        self.plugin_manager._opensearch_config.update_plugin.assert_called_once_with(
            {"knn.plugin.enabled": None}
        )

        mock_api_request.assert_called_once_with(
            "PUT",
            "/_cluster/settings?flat_settings=true",
            payload='{"persistent": {"knn.plugin.enabled": null} }',
        )
        # It means we correctly cleaned the cache
        mock_cluster_config.__delete__.assert_called_once()
