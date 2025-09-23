# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Objects representing the state of OpenSearchBaseCharm."""


import logging
from functools import cached_property
from typing import TYPE_CHECKING, Dict, Optional

from charms.opensearch.v0.constants_charm import PERFORMANCE_PROFILE, PeerRelationName
from charms.opensearch.v0.models import (
    DeploymentDescription,
    PeerClusterApp,
    PerformanceType,
)
from ops import Object

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

from charms.opensearch.v0.opensearch_internal_data import RelationDataStore, Scope
from charms.opensearch.v0.opensearch_profile import (
    OpenSearchProfile,
    ProductionProfile,
    TestingProfile,
)

logger = logging.getLogger(__name__)


class OpenSearchApp:
    """State/Relation data collection for an opensearch application (juju app)."""

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ):
        self.scope = Scope.APP
        self.relation_data = RelationDataStore(charm, PeerRelationName)

    @property
    def cluster_fleet_apps(self) -> Dict[str, PeerClusterApp]:
        """Get the cluster fleet applications."""
        cluster_fleet_apps = self.relation_data.get_object(self.scope, "cluster_fleet_apps") or {}
        return {id: PeerClusterApp.from_dict(app) for id, app in cluster_fleet_apps.items()}

    @property
    def deployment_description(self) -> DeploymentDescription | None:
        """Return DeploymentDescription from peer relation"""
        deployment_desc_dict = self.relation_data.get_object(self.scope, "deployment-description")
        if not deployment_desc_dict:
            return None
        return DeploymentDescription.from_dict(deployment_desc_dict)


class OpenSearchUnit:
    """State/Relation data collection for an opensearch node (juju unit)."""

    def __init__(
        self,
        charm: "OpenSearchBaseCharm",
    ):
        self.scope = Scope.UNIT
        self.relation_data = RelationDataStore(charm, PeerRelationName)

    @property
    def profile(self) -> Optional[OpenSearchProfile]:
        """Current profile of the unit"""
        if profile_str := self.relation_data.get(self.scope, PERFORMANCE_PROFILE, None):
            return (
                ProductionProfile()
                if PerformanceType(profile_str) == PerformanceType.PRODUCTION
                else TestingProfile()
            )
        return None


class OpenSearchClusterState(Object):
    """Global state object for an opensearch cluster"""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(parent=charm, key="charm_state")
        self.charm = charm
        self.config = charm.config

    @cached_property
    def app(self) -> OpenSearchApp:
        """Get state of the local opensearch app."""
        return OpenSearchApp(
            charm=self.charm,
        )

    @cached_property
    def unit(self) -> OpenSearchUnit:
        """Get state of the local opensearch unit."""
        return OpenSearchUnit(
            charm=self.charm,
        )
