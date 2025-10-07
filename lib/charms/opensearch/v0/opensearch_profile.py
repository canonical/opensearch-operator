# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Represents the profile of the OpenSearch cluster.

The main goals of this library is to provide a way to manage the
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

from charms.opensearch.v0.constants_charm import InvalidProfileConfigOption
from charms.opensearch.v0.helper_cluster import ClusterTopology
from ops import BlockedStatus

if TYPE_CHECKING:
    from charms.opensearch.v0.state import OpenSearchClusterState
    from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution

from charms.opensearch.v0.helper_charm import Status, all_units, format_unit_name
from charms.opensearch.v0.models import (
    Model,
    PeerClusterApp,
    PerformanceType,
    StartMode,
)

# The unique Charmhub library identifier, never change it
LIBID = "8b7aa39016e748ea908787df1d7fb089"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2


logger = logging.getLogger(__name__)


_1GB_IN_KB = 1024 * 1024  # 1GB in KB
MAX_HEAP_SIZE = 31 * _1GB_IN_KB  # 31GB in KB


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

    def __hash__(self):
        """Get the hash of the profile."""
        return hash(self.type)

    def __eq__(self, value: object) -> bool:
        """Check equality with another OpenSearchProfile."""
        return self.type == value.type if isinstance(value, OpenSearchProfile) else False


class ProductionProfile(OpenSearchProfile):
    """Production profile for opensearch.

    Ensures cluster meets production minimal requirements
    """

    type = PerformanceType.PRODUCTION

    @property
    def memory_requirements(self) -> ProfileMemoryRequirements:
        """Get the memory requirements for this profile."""
        return ProfileMemoryRequirements(
            memory_size=8 * _1GB_IN_KB,
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
        try:
            if self.profile.type == PerformanceType.TESTING:
                logger.warning(
                    "Testing profile is used. This profile is not suitable for production use and should only be used for testing purposes."
                )
        except ValueError:
            logger.error(
                "Invalid profile configuration. Value: %s", self.state.config.get("profile")
            )

    def check_missing_system_requirements(self) -> List[str]:
        """Checks the system requirements."""
        return self.workload.check_missing_system_requirements()

    def check_memory_requirements(self, profile: OpenSearchProfile) -> List[str]:
        """Checks memory requirements for the unit."""
        memory_size = self.workload.meminfo()["MemTotal"]

        if (
            profile.memory_requirements.memory_size
            and memory_size < profile.memory_requirements.memory_size
        ):
            logger.error(
                "Insufficient memory: %s < %s",
                memory_size,
                profile.memory_requirements.memory_size,
            )
            return [
                "Insufficient memory: %s < %s"
                % (memory_size, profile.memory_requirements.memory_size)
            ]

        return []

    def check_cluster_topology(self, profile: OpenSearchProfile) -> List[str]:
        """Check the cluster topology requirements."""
        cluster_fleet_apps = self.state.app.cluster_fleet_apps
        current_app = self._current_peer_cluster_app()
        # backwards compatibility for revisions that do not set generated roles
        # in cluster_fleet_apps
        if not cluster_fleet_apps or current_app.app.id in cluster_fleet_apps:
            cluster_fleet_apps[current_app.app.id] = current_app

        logger.debug("current_cluster_fleet_apps: %s", cluster_fleet_apps)
        error_message = None

        nbr_cm_nodes = sum(
            app.planned_units
            for app in cluster_fleet_apps.values()
            if "cluster_manager" in app.roles
        )
        nbr_data_nodes = sum(
            app.planned_units for app in cluster_fleet_apps.values() if "data" in app.roles
        )

        match nbr_cm_nodes < profile.cluster_topology_requirements.cluster_managers, nbr_data_nodes < profile.cluster_topology_requirements.data:
            case (True, True):
                error_message = f"At least {profile.cluster_topology_requirements.cluster_managers} cluster manager nodes and {profile.cluster_topology_requirements.data} data nodes are required."
            case (True, False):
                error_message = f"At least {profile.cluster_topology_requirements.cluster_managers} cluster manager nodes are required."
            case (False, True):
                error_message = f"At least {profile.cluster_topology_requirements.data} data nodes are required."
            case _:
                return []

        logger.error("Missing cluster topology requirements: %s", error_message)
        return [error_message]

    def check_missing_requirements(self, set_status: bool = True) -> List[str]:
        """Check all requirements of profile

        Requirements include:
        - System requirements
        - Memory requirements
        - Cluster topology requirements
        """
        missing_requirements: List[str] = []
        try:
            profile = self.config_profile
        except ValueError:
            logger.error(
                "Invalid profile configuration. Value: %s", self.state.config.get("profile")
            )
            self.state.charm.status.set(BlockedStatus(InvalidProfileConfigOption))
            return [InvalidProfileConfigOption]

        missing_requirements.extend(self.check_missing_system_requirements())
        missing_requirements.extend(self.check_memory_requirements(profile))
        missing_requirements.extend(self.check_cluster_topology(profile))

        if set_status:
            if missing_requirements:
                logger.error("Missing profile requirements: %s", missing_requirements)
                self.state.charm.status.set(
                    BlockedStatus(f"Missing requirements: {' - '.join(missing_requirements)}")
                )
            else:
                self.state.charm.status.clear(
                    status_message="Missing requirements:", pattern=Status.CheckPattern.Start
                )

        return missing_requirements

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

    @property
    def profile(self) -> OpenSearchProfile:
        """Get the current profile."""
        return self.state.unit.profile or self.config_profile

    @property
    def config_profile(self) -> OpenSearchProfile:
        """Get the current config profile."""
        return (
            ProductionProfile()
            if PerformanceType(self.state.config.get("profile")) == PerformanceType.PRODUCTION
            else TestingProfile()
        )
