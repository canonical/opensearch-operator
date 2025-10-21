# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from charms.opensearch.v0.constants_charm import GeneratedRoles
from charms.opensearch.v0.models import (
    App,
    DeploymentDescription,
    DeploymentType,
    PeerClusterApp,
    PeerClusterConfig,
    StartMode,
)
from charms.opensearch.v0.opensearch_profile import (
    _1GB_IN_KB,
    ClusterTopologyRequirements,
    ProductionProfile,
    ProfileMemoryRequirements,
    TestingProfile,
)
from ops import ActiveStatus
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


@pytest.fixture
def mock_meminfo():
    with patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.meminfo") as mock:
        mock.return_value = {"MemTotal": 8000000}  # 8 GB in kB
        yield mock


def test_production_profile():
    production_profile = ProductionProfile()
    assert production_profile.memory_requirements == ProfileMemoryRequirements(
        memory_size=8 * _1GB_IN_KB, jvm_heap_percentage=0.5
    )
    assert production_profile.cluster_topology_requirements == ClusterTopologyRequirements(
        cluster_managers=3, data=3
    )


def test_testing_profile():
    testing_profile = TestingProfile()
    assert testing_profile.memory_requirements == ProfileMemoryRequirements(
        memory_size=None, jvm_heap_percentage=None
    )
    assert testing_profile.cluster_topology_requirements == ClusterTopologyRequirements(
        cluster_managers=1, data=1
    )


# We need to simulate the original value of jvm.options
JVM_OPTIONS = """-Xms1g
-Xmx1g"""

MEMINFO = """MemTotal:        15728640 kB
MemFree:          1234 kB
NotValid:         0
"""


class TestPerformanceProfile(unittest.TestCase):

    def setUp(self):
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(True)
        with patch(
            "charms.opensearch.v0.opensearch_profile.ProfilesManager.config_profile",
            new_callable=PropertyMock,
            return_value=ProductionProfile(),
        ):
            self.harness.begin()
            self.charm = self.harness.charm
            self.charm.status.set(ActiveStatus())
            self.opensearch = self.charm.opensearch

    def test_profile_update_on_config_changed_system_requirement_not_met(self):
        """Test the update of the JVM options."""
        with (
            patch(
                "charms.opensearch.v0.state.OpenSearchApp.deployment_description",
                new_callable=PropertyMock,
                return_value=DeploymentDescription(
                    app=App(id="opensearch"),
                    config=PeerClusterConfig(
                        cluster_name="opensearch", init_hold=False, roles=GeneratedRoles
                    ),
                    start=StartMode.WITH_GENERATED_ROLES,
                    pending_directives=[],
                    typ=DeploymentType.MAIN_ORCHESTRATOR,
                    promotion_time=1,
                ),
            ),
            patch(
                "charms.opensearch.v0.opensearch_config.OpenSearchConfig.update_host_if_needed",
                return_value=False,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up",
                return_value=True,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._apply_system_requirement",
                return_value=False,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._get_kernel_property_value",
                return_value=10,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.meminfo",
                return_value={"MemTotal": 15.0 * _1GB_IN_KB},
            ),
            patch(
                "charms.opensearch.v0.opensearch_profile.ProfilesManager._current_peer_cluster_app",
                return_value=PeerClusterApp(
                    app=App(id="opensearch"),
                    roles=["cluster_manager", "data"],
                    planned_units=3,
                    units=["1", "2", "3"],
                ),
            ),
        ):
            self.charm._on_config_changed(MagicMock())
            assert self.charm.unit.status.name == "blocked"
            assert "vm.max_map_count should be at least 262144" in self.charm.unit.status.message

    def test_profile_update_on_config_changed_memory_not_met(self):
        """Test the update of the JVM options."""
        with (
            patch(
                "charms.opensearch.v0.opensearch_config.OpenSearchConfig.update_host_if_needed",
                return_value=False,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up",
                return_value=True,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._apply_system_requirement",
                return_value=True,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.meminfo",
                return_value={"MemTotal": 3.0 * _1GB_IN_KB},
            ),
            patch(
                "charms.opensearch.v0.opensearch_profile.ProfilesManager._current_peer_cluster_app",
                return_value=PeerClusterApp(
                    app=App(id="opensearch"),
                    roles=["cluster_manager", "data"],
                    planned_units=3,
                    units=["1", "2", "3"],
                ),
            ),
            patch(
                "charms.opensearch.v0.opensearch_profile.ProfilesManager.config_profile",
                new_callable=PropertyMock,
                return_value=ProductionProfile(),
            ),
            patch(
                "charms.opensearch.v0.state.OpenSearchApp.deployment_description",
                new_callable=PropertyMock,
                return_value=DeploymentDescription(
                    app=App(id="opensearch"),
                    config=PeerClusterConfig(
                        cluster_name="opensearch", init_hold=False, roles=GeneratedRoles
                    ),
                    start=StartMode.WITH_GENERATED_ROLES,
                    pending_directives=[],
                    typ=DeploymentType.MAIN_ORCHESTRATOR,
                    promotion_time=1,
                ),
            ),
        ):
            self.charm._on_config_changed(MagicMock())
            assert self.charm.unit.status.name == "blocked"
            assert "Insufficient memory" in self.charm.unit.status.message

    def test_profile_update_on_config_cluster_topology_not_met(self):
        """Test the update of the JVM options."""
        with (
            patch(
                "charms.opensearch.v0.state.OpenSearchApp.deployment_description",
                new_callable=PropertyMock,
                return_value=DeploymentDescription(
                    app=App(id="opensearch"),
                    config=PeerClusterConfig(
                        cluster_name="opensearch", init_hold=False, roles=GeneratedRoles
                    ),
                    start=StartMode.WITH_GENERATED_ROLES,
                    pending_directives=[],
                    typ=DeploymentType.MAIN_ORCHESTRATOR,
                    promotion_time=1,
                ),
            ),
            patch(
                "charms.opensearch.v0.opensearch_config.OpenSearchConfig.update_host_if_needed",
                return_value=False,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up",
                return_value=True,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._apply_system_requirement",
                return_value=True,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.meminfo",
                return_value={"MemTotal": 4.0 * _1GB_IN_KB},
            ),
            patch(
                "charms.opensearch.v0.opensearch_profile.ProfilesManager._current_peer_cluster_app",
                return_value=PeerClusterApp(
                    app=App(id="opensearch"),
                    roles=["cluster_manager", "data"],
                    planned_units=1,
                    units=["1"],
                ),
            ),
            patch(
                "charms.opensearch.v0.opensearch_profile.ProfilesManager.config_profile",
                new_callable=PropertyMock,
                return_value=ProductionProfile(),
            ),
        ):
            self.charm._on_config_changed(MagicMock())
            assert self.charm.unit.status.name == "blocked"
            assert (
                "At least 3 cluster manager nodes and 3 data nodes are required"
                in self.charm.unit.status.message
            )

    def test_profile_update_on_config_happy_path(self):
        """Test the update of the JVM options."""
        with (
            patch(
                "charms.opensearch.v0.state.OpenSearchApp.deployment_description",
                new_callable=PropertyMock,
                return_value=DeploymentDescription(
                    app=App(id="opensearch"),
                    config=PeerClusterConfig(
                        cluster_name="opensearch", init_hold=False, roles=GeneratedRoles
                    ),
                    start=StartMode.WITH_GENERATED_ROLES,
                    pending_directives=[],
                    typ=DeploymentType.MAIN_ORCHESTRATOR,
                    promotion_time=1,
                ),
            ),
            patch(
                "charms.opensearch.v0.opensearch_config.OpenSearchConfig.update_host_if_needed",
                return_value=False,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up",
                return_value=True,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._apply_system_requirement",
                return_value=True,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.meminfo",
                return_value={"MemTotal": 8.0 * _1GB_IN_KB},
            ),
            patch(
                "charms.opensearch.v0.state.OpenSearchApp.cluster_fleet_apps",
                new_callable=PropertyMock(
                    return_value={
                        "opensearch": PeerClusterApp(
                            app=App(id="opensearch"),
                            roles=["cluster_manager", "data"],
                            planned_units=3,
                            units=["1", "2", "3"],
                        ),
                    }
                ),
            ),
            patch(
                "charms.opensearch.v0.opensearch_profile.ProfilesManager._current_peer_cluster_app",
                return_value=PeerClusterApp(
                    app=App(id="opensearch"),
                    roles=["cluster_manager", "data"],
                    planned_units=3,
                    units=["1", "2", "3"],
                ),
            ),
            patch(
                "charms.opensearch.v0.opensearch_config.OpenSearchConfig.set_jvm_heap_size",
            ) as set_jvm_heap_size,
            patch(
                "charms.opensearch.v0.opensearch_profile.ProfilesManager.config_profile",
                new_callable=PropertyMock,
                return_value=ProductionProfile(),
            ),
        ):
            self.charm._on_config_changed(MagicMock())
            set_jvm_heap_size.assert_called_with(4194304)

    def test_profile_update_on_start_blocked(self):
        """Test the update of the JVM options."""
        with (
            patch(
                "charms.opensearch.v0.opensearch_config.OpenSearchConfig.update_host_if_needed",
                return_value=False,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_node_up",
                return_value=False,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._apply_system_requirement",
                return_value=True,
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.meminfo",
                return_value={"MemTotal": 4.0 * _1GB_IN_KB},
            ),
            patch(
                "charms.opensearch.v0.state.OpenSearchApp.cluster_fleet_apps",
                new_callable=PropertyMock(
                    return_value={
                        "opensearch": PeerClusterApp(
                            app=App(id="opensearch"),
                            roles=["cluster_manager", "data"],
                            planned_units=3,
                            units=["1", "2", "3"],
                        ),
                    }
                ),
            ),
            patch(
                "charms.opensearch.v0.state.OpenSearchApp.deployment_description",
                new_callable=PropertyMock,
                return_value=DeploymentDescription(
                    app=App(id="opensearch"),
                    config=PeerClusterConfig(
                        cluster_name="opensearch", init_hold=False, roles=GeneratedRoles
                    ),
                    start=StartMode.WITH_GENERATED_ROLES,
                    pending_directives=[],
                    typ=DeploymentType.MAIN_ORCHESTRATOR,
                    promotion_time=1,
                ),
            ),
            patch(
                "charms.opensearch.v0.opensearch_profile.ProfilesManager._current_peer_cluster_app",
                return_value=PeerClusterApp(
                    app=App(id="opensearch"),
                    roles=["cluster_manager", "data"],
                    planned_units=3,
                    units=["1", "2", "3"],
                ),
            ),
            patch(
                "charms.opensearch.v0.opensearch_config.OpenSearchConfig.set_jvm_heap_size",
            ),
            patch(
                "charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.is_started",
                return_value=False,
            ),
            patch(
                "charms.opensearch.v0.opensearch_profile.ProfilesManager.config_profile",
                new_callable=PropertyMock,
                return_value=ProductionProfile(),
            ),
        ):
            self.charm._start_opensearch(MagicMock(ignore_lock=False))
            assert self.charm.unit.status.name == "blocked"
            assert "Insufficient memory" in self.charm.unit.status.message
