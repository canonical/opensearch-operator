#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of global cluster state."""
import logging
from typing import Dict, Optional, Set

from charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerOtherUnitData,
    DataPeerUnitData,
    OpenSearchRequiresData,
)
from core.models import SUBSTRATES, ODCluster, ODServer, OpensearchServer
from literals import (
    DASHBOARD_INDEX,
    OPENSEARCH_REL_NAME,
    PEER,
    PEER_APP_SECRETS,
    PEER_UNIT_SECRETS,
)
from ops.framework import Framework, Object
from ops.model import Relation, Unit

logger = logging.getLogger(__name__)


class ClusterState(Object):
    """Collection of global cluster state for Framework/Object."""

    def __init__(self, charm: Framework | Object, substrate: SUBSTRATES):
        super().__init__(parent=charm, key="charm_state")
        self.substrate: SUBSTRATES = substrate
        self._servers_data = {}

        self.peer_app_data = DataPeerData(
            self.model, relation_name=PEER, additional_secret_fields=PEER_APP_SECRETS
        )
        self.peer_unit_data = DataPeerUnitData(
            self.model, relation_name=PEER, additional_secret_fields=PEER_UNIT_SECRETS
        )
        self.client_requires_data = OpenSearchRequiresData(
            self.model,
            relation_name=OPENSEARCH_REL_NAME,
            index=DASHBOARD_INDEX,
            extra_user_roles="kibana_server",
        )

    # --- RAW RELATION ---

    @property
    def peer_relation(self) -> Relation | None:
        """The cluster peer relation."""
        return self.model.get_relation(PEER)

    @property
    def opensearch_relation(self) -> Optional[Relation]:
        """The Opensearch Server relation."""
        return self.model.get_relation(OPENSEARCH_REL_NAME)

    # --- CORE COMPONENTS---

    @property
    def unit_server(self) -> ODServer:
        """The server state of the current running Unit."""
        return ODServer(
            relation=self.peer_relation,
            data_interface=self.peer_unit_data,
            component=self.model.unit,
            substrate=self.substrate,
        )

    @property
    def peer_units_data(self) -> Dict[Unit, DataPeerOtherUnitData]:
        """The cluster peer relation."""
        if not self.peer_relation or not self.peer_relation.units:
            return {}

        for unit in self.peer_relation.units:
            if unit not in self._servers_data:
                self._servers_data[unit] = DataPeerOtherUnitData(
                    model=self.model, unit=unit, relation_name=PEER
                )
        return self._servers_data

    @property
    def cluster(self) -> ODCluster:
        """The cluster state of the current running App."""
        return ODCluster(
            relation=self.peer_relation,
            data_interface=self.peer_app_data,
            component=self.model.app,
            substrate=self.substrate,
        )

    @property
    def servers(self) -> Set[ODServer]:
        """Grabs all servers in the current peer relation, including the running unit server.

        Returns:
            Set of ODServers in the current peer relation, including the running unit server.
        """
        if not self.peer_relation:
            return set()

        servers = set()
        for unit, data_interface in self.peer_units_data.items():
            servers.add(
                ODServer(
                    relation=self.peer_relation,
                    data_interface=data_interface,
                    component=unit,
                    substrate=self.substrate,
                )
            )
        servers.add(self.unit_server)

        return servers

    @property
    def opensearch_server(self) -> Optional[OpensearchServer]:
        """The state for all related client Applications."""
        if not self.opensearch_relation or not self.opensearch_relation.app:
            return None

        # We assume no more than 1 server relation
        return OpensearchServer(
            relation=self.opensearch_relation,
            data_interface=self.client_requires_data,
            component=self.opensearch_relation.app,
            substrate=self.substrate,
            local_app=self.cluster.app,
            tls=self.cluster.tls,
        )

    # --- CLUSTER INIT ---

    @property
    def endpoints(self) -> list[str]:
        """The connection uris for all started units.

        Returns:
            List of unit addresses
        """
        return sorted(
            [
                server.host if self.substrate == "k8s" else server.private_ip
                for server in self.servers
            ]
        )

    @property
    def started_servers(self) -> Set[ODServer]:
        """The server states of all started peer-related Units."""
        return {server for server in self.servers if server.started}

    @property
    def all_units_related(self) -> bool:
        """Checks if currently related units make up all planned units.

        Returns:
            True if all units are related. Otherwise False
        """
        return len(self.servers) == self.model.app.planned_units()

    # --- HEALTH ---

    # @property
    # def healthy(self) -> bool:
    #     """Flag to check if the cluster is safe to update members."""
    #     # TBD
    #     return True

    @property
    def stable(self) -> bool:
        """Flag to check if the quorum is in a stable state, with all members up-to-date."""
        if not self.all_units_related:
            logger.debug("cluster not stable - not all units related")
            return False

        return True
