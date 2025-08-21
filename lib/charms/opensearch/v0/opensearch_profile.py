# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Represents the performance profile of the OpenSearch cluster.

The main goals of this library is to provide a way to manage the performance
profile of the OpenSearch cluster.

There are two ways the charm can learn about its profile and when it changes:
1) If this is the MAIN_ORCHESTRATOR: config-changed -> the user has switched the profile directly
2) If not the MAIN_ORCHESTRATOR: peer-cluster-relation-changed -> the main orchestrator has
                                 switched the profile

The charm will then apply the profile and restart the OpenSearch service if needed.
"""
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Optional

from charms.opensearch.v0.helper_cluster import ClusterTopology

if TYPE_CHECKING:
    from charms.opensearch.v0.state import OpenSearchClusterState
    from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution

from charms.opensearch.v0.helper_charm import all_units, format_unit_name
from charms.opensearch.v0.models import (
    Model,
    PeerClusterApp,
    PerformanceType,
    StartMode,
)
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError

# The unique Charmhub library identifier, never change it
LIBID = "8b7aa39016e748ea908787df1d7fb089"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2


logger = logging.getLogger(__name__)


_1GB_IN_KB = 1024 * 1024  # 1GB in KB
MAX_HEAP_SIZE = 31 * _1GB_IN_KB  # 32GB in KB


class ProfileMemoryRequirements(Model):
    """Memory requirements for a profile"""

    memory_size: Optional[int] = None
    jvm_heap_percentage: Optional[float] = None


class ClusterTopologyRequirements(Model):
    """Cluster Topology requirements for a profile"""

    cluster_managers: int = 1
    data: int = 1


class OpenSearchProfile(ABC):
    """Abstract class for an OpenSearch profile"""

    type: PerformanceType

    @property
    @abstractmethod
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile"""
        pass

    @property
    @abstractmethod
    def cluster_topology_requirements(self) -> ClusterTopologyRequirements:
        """Get the cluster topology requirements for this profile."""
        pass

    def get_jvm_heap_size(self, mem_size: float) -> int:
        """Get the JVM heap size in KB based on the memory requirements."""
        if self.memory_requirements.jvm_heap_percentage:
            return min(int(self.memory_requirements.jvm_heap_percentage * mem_size), MAX_HEAP_SIZE)
        return _1GB_IN_KB


class ProductionProfile(OpenSearchProfile):
    """Production profile for opensearch.

    Ensures cluster meets production minimal requirements
    """

    type = PerformanceType.PRODUCTION

    @property
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile."""
        return ProfileMemoryRequirements(
            memory_size=4 * _1GB_IN_KB,  # 4GB in KB
            jvm_heap_percentage=0.5,
        )

    @property
    def cluster_topology_requirements(self) -> ClusterTopologyRequirements:
        """Get the cluster topology requirements for this profile."""
        return ClusterTopologyRequirements(
            cluster_managers=3,
            data=3,
        )


class TestingProfile(OpenSearchProfile):
    """Testing profile for opensearch.

    Ensures basic system requirements and 1 CM+ 1 Data roles.
    """

    type = PerformanceType.TESTING

    @property
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile."""
        return ProfileMemoryRequirements(
            memory_size=None,
            jvm_heap_percentage=None,
        )

    @property
    def cluster_topology_requirements(self) -> ClusterTopologyRequirements:
        """Get the cluster topology requirements for this profile."""
        return ClusterTopologyRequirements(
            cluster_managers=1,
            data=1,
        )


class ProfilesManager:
    """Manage all profile related operations"""

    def __init__(self, state: "OpenSearchClusterState", workload: "OpenSearchDistribution"):
        self.state = state
        self.workload = workload
        self.profile = self.state.unit.profile or self.get_config_profile()
        if self.profile.type == PerformanceType.TESTING:
            logger.warning(
                "Testing profile is used. This profile is not suitable for production use and should only be used for testing purposes."
            )

    def _apply_system_requirement(self, system_requirement: str, value: int) -> bool:
        """Apply a system requirement."""
        try:
            self.workload._run_cmd(f"sysctl -w {system_requirement}={value}")
            return int(self.workload._run_cmd(f"sysctl -n {system_requirement}")) == value
        except OpenSearchCmdError:
            return False

    def _get_kernel_property_value(self, prop: str) -> int:
        """Get the value of a kernel parameter."""
        return int(self.workload._run_cmd(f"sysctl -n {prop}"))

    def check_missing_system_requirements(self) -> List[str]:
        """Checks the system requirements."""
        missing_requirements = []

        prop, val = "vm.max_map_count", 262144
        if self._get_kernel_property_value(prop) < val and not self._apply_system_requirement(
            prop, val
        ):
            missing_requirements.append(f"{prop} should be at least {val}")

        prop, val = "vm.swappiness", 1
        if self._get_kernel_property_value(prop) > val and not self._apply_system_requirement(
            prop, 0
        ):
            missing_requirements.append(f"{prop} should be at most 1")

        prop, val = "net.ipv4.tcp_retries2", 5
        if self._get_kernel_property_value(prop) > val and not self._apply_system_requirement(
            prop, val
        ):
            missing_requirements.append(f"{prop} should be at most {val}")

        return missing_requirements

    def check_memory_requirements(self, profile: OpenSearchProfile) -> List[str]:
        """Checks memory requirements for the unit."""
        memory_size = self.workload.meminfo()["MemTotal"]

        if (
            profile.memory_requirements.memory_size
            and memory_size < profile.memory_requirements.memory_size
        ):
            logger.error(
                f"Insufficient memory: {memory_size} < {profile.memory_requirements.memory_size}"
            )
            return [
                f"Insufficient memory: {memory_size} < {profile.memory_requirements.memory_size}"
            ]

        return []

    def check_cluster_topology(self, profile: OpenSearchProfile) -> List[str]:
        """Check the cluster topology requirements."""
        cluster_fleet_apps = self.state.app.cluster_fleet_apps or [
            self._current_peer_cluster_app()
        ]
        logger.debug(f"current_cluster_fleet_apps: {cluster_fleet_apps}")
        missing_requirements = []

        nbr_cm_nodes = sum(
            app.planned_units for app in cluster_fleet_apps if "cluster_manager" in app.roles
        )
        nbr_data_nodes = sum(
            app.planned_units for app in cluster_fleet_apps if "data" in app.roles
        )

        if nbr_cm_nodes < profile.cluster_topology_requirements.cluster_managers:
            missing_requirements.append(
                f"At least {profile.cluster_topology_requirements.cluster_managers} cluster manager nodes are required. Found only {nbr_cm_nodes}."
            )

        if nbr_data_nodes < profile.cluster_topology_requirements.data:
            missing_requirements.append(
                f"At least {profile.cluster_topology_requirements.data} data nodes are required. Found only {nbr_data_nodes}."
            )

        return missing_requirements

    def check_all_requirements(self, profile: Optional[OpenSearchProfile] = None) -> List[str]:
        """Check all requirements of profile

        Requirements include:
        - System requirements
        - Memory requirements
        - Cluster topology requirements
        """
        if profile is None:
            profile = self.profile
        missing_requirements: List[str] = []

        missing_requirements.extend(self.check_missing_system_requirements())
        missing_requirements.extend(self.check_memory_requirements(profile))
        missing_requirements.extend(self.check_cluster_topology(profile))

        return missing_requirements

    def get_config_profile(self) -> OpenSearchProfile:
        """Get the current config profile."""
        return (
            ProductionProfile()
            if PerformanceType(self.state.config.get("profile")) == PerformanceType.PRODUCTION
            else TestingProfile()
        )

    def _current_peer_cluster_app(self) -> PeerClusterApp:
        deployment_desc = self.state.app.deployment_description
        return PeerClusterApp(
            app=deployment_desc.app,
            planned_units=self.state.charm.app.planned_units(),
            units=[
                format_unit_name(u, app=deployment_desc.app) for u in all_units(self.state.charm)
            ],
            roles=(
                deployment_desc.config.roles
                if deployment_desc.start == StartMode.WITH_PROVIDED_ROLES
                else ClusterTopology.generated_roles()
            ),
        )
