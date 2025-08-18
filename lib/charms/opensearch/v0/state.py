# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Objects representing the state of OpenSearchBaseCharm."""


import json
import logging
from typing import TYPE_CHECKING, List, Optional

from charms.data_platform_libs.v0.data_interfaces import (
    Data,
    DataPeerData,
    DataPeerUnitData,
)
from charms.opensearch.v0.constants_charm import PERFORMANCE_PROFILE, PeerRelationName
from charms.opensearch.v0.models import DeploymentDescription, PeerClusterApp, PerformanceType
from ops import Application, Object, Relation, Unit

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

from charms.opensearch.v0.opensearch_profile import (
    OpenSearchProfile,
    ProductionProfile,
    TestingProfile,
)

logger = logging.getLogger(__name__)


class RelationState:
    """Relation state object."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Unit | Application | None,
        # substrate: SUBSTRATES,
    ):
        self.relation = relation
        self.data_interface = data_interface
        self.component = component
        # self.substrate = substrate
        self.relation_data = self.data_interface.as_dict(self.relation.id) if self.relation else {}

    def update(self, items: dict[str, str]) -> None:
        """Write to relation data."""
        if not self.relation:
            logger.warning(
                f"Fields {list(items.keys())} were attempted to be written on the relation before it exists."
            )
            return

        delete_fields = [key for key in items if not items[key]]
        update_content = {k: items[k] for k in items if k not in delete_fields}

        self.relation_data.update(update_content)

        for field in delete_fields:
            # use del instead of pop here because of error with dataplatform-libs
            try:
                del self.relation_data[field]
            except KeyError:
                pass


class OpenSearchApp(RelationState):
    """State/Relation data collection for an opensearch application (juju app)."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerData,
        component: Application,
        # substrate: SUBSTRATES,
    ):
        super().__init__(relation, data_interface, component)
        self.app = component

    @property
    def cluster_fleet_apps(self) -> List[PeerClusterApp]:
        """Get the cluster fleet applications."""
        cluster_fleet_apps = json.loads(self.relation_data.get("cluster_fleet_apps", "{}"))
        return [PeerClusterApp.from_dict(app) for app in cluster_fleet_apps.values()]

    @property
    def profile(self) -> Optional[OpenSearchProfile]:
        """Current profile of the unit"""
        if profile_str := self.relation_data.get(PERFORMANCE_PROFILE, None):
            return (
                TestingProfile()
                if PerformanceType(profile_str) == PerformanceType.TESTING
                else ProductionProfile()
            )
        return None

    @profile.setter
    def profile(self, new_profile: OpenSearchProfile):
        """Set the performance profile for the node."""
        self.update({PERFORMANCE_PROFILE: new_profile.type.value})

    @property
    def deployment_description(self) -> DeploymentDescription | None:
        """Return DeploymentDescription from peer relation"""
        deployment_desc_dict = json.loads(self.relation_data.get("deployment-description", "{}"))
        if not deployment_desc_dict:
            return None
        return DeploymentDescription.from_dict(deployment_desc_dict)


class OpenSearchNode(RelationState):
    """State/Relation data collection for an opensearch node (juju unit)."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerUnitData,
        component: Unit,
        # substrate: SUBSTRATES,
    ):
        super().__init__(relation, data_interface, component)
        self.unit = component


class OpenSearchClusterState(Object):
    """Global state object for an opensearch cluster"""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(parent=charm, key="charm_state")
        self.charm = charm
        self.peer_app_interface = DataPeerData(
            self.model,
            relation_name=PeerRelationName,  # additional_secret_fields=SECRETS_APP
        )
        self.peer_unit_interface = DataPeerUnitData(self.model, relation_name=PeerRelationName)
        self.config = charm.config

    @property
    def peer_relation(self) -> Relation | None:
        """Get the cluster peer relation."""
        return self.model.get_relation(PeerRelationName)

    @property
    def app(self) -> OpenSearchApp:
        """Get state of the local opensearch app."""
        return OpenSearchApp(
            relation=self.peer_relation,
            data_interface=self.peer_app_interface,
            component=self.model.app,
        )

    @property
    def unit(self) -> OpenSearchNode:
        """Get state of the local opensearch unit."""
        return OpenSearchNode(
            relation=self.peer_relation,
            data_interface=self.peer_unit_interface,
            component=self.model.unit,
        )
