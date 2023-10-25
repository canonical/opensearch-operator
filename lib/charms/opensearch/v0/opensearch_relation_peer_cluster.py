# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Peer clusters relation related classes for OpenSearch."""
import logging
from typing import TYPE_CHECKING, List, Optional, Union

from charms.opensearch.v0.constants_charm import PeerClusterRelationName
from charms.opensearch.v0.constants_secrets import ADMIN_PW, ADMIN_PW_HASH
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.models import (
    DeploymentType,
    PeerClusterRelData,
    PeerClusterRelDataCredentials,
    PeerClusterRelErrorData, Node,
)
from charms.opensearch.v0.opensearch_exceptions import OpenSearchError, OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import Object, RelationChangedEvent, RelationDepartedEvent, RelationJoinedEvent, EventBase, BlockedStatus

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm


logger = logging.getLogger(__name__)


# The unique Charmhub library identifier, never change it
LIBID = "5f54c024d6a2405f9c625cf832c302db"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class OpenSearchPeerClusterRelationError(OpenSearchError):
   pass


class OpenSearchPeerClusterProviderError(OpenSearchPeerClusterRelationError):
   """Peer cl"""
   pass


class OpenSearchPeerClusterRequirerError(OpenSearchPeerClusterRelationError):
   pass


class OpenSearchPeerClusterProvider(Object):
    """Peer cluster relation provider class."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, PeerClusterRelationName)

        self._charm = charm
        self._opensearch = charm.opensearch
        self._peer_cm = charm.opensearch_peer_cm

        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_joined, self._on_peer_cluster_relation_joined
        )
        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_changed, self._on_peer_cluster_relation_changed
        )
        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_departed, self._on_peer_cluster_relation_departed,
        )
        # todo how to differentiate between current cluster leaving
        # the relation vs sub-cluster leaving

    def _on_peer_cluster_relation_joined(self, event: RelationJoinedEvent):
        """Event received by all units in sub-cluster when a new sub-cluster joins the relation."""
        self.refresh_relation_data(event)

    def refresh_relation_data(self, event: EventBase):
        """Refresh the peer cluster rel data (new cm node, admin password change etc.)."""
        if not self._charm.unit.is_leader():
            return

        peer_rel_data_key = "data"

        rel_data = self._rel_data()
        if isinstance(rel_data, PeerClusterRelErrorData):
            peer_rel_data_key = "error_data"
            if rel_data.should_wait:
                event.defer()
        else:
            self._peer_cm.peer_cluster_data.delete("error_data")

        self._peer_cm.peer_cluster_data.put_object(
            Scope.APP, peer_rel_data_key, rel_data.to_dict()
        )

    def _on_peer_cluster_relation_changed(self, event: RelationChangedEvent):
        """Event received by all units in sub-cluster when a new sub-cluster joins the relation."""
        if not self._charm.unit.is_leader():
            return

    def _on_peer_cluster_relation_departed(self, event: RelationDepartedEvent):
        """Event received by all units in sub-cluster when a sub-cluster leaves the relation."""
        logger.info(f"\n\n_on_peer_cluster_relation_departed:\n{event}\n\n\n")

        # this is where sub-clusters configured to auto-generated should probably recompute
        # should the one with "min(rel_id)" propose to change?
        pass

    def _is_ready_for_relation(self) -> bool:
        """Check if the current cluster is ready to take on a Peer Cluster relation."""
        """# if primary CM
            # check if admin user initialized
            # tls configured
            # nodes up
            # whenever new CM joins current ==> update relation data
        # if secondary CM
            # is it related to a primary CM ??
            # is there a peer_rel data object shared with me
            # check on CM list"""
        pass

    def _rel_data(self) -> Union[PeerClusterRelData, PeerClusterRelErrorData]:
        """Build and return the peer cluster rel data to be shared with requirer sub-clusters."""
        rel_err_data = self._rel_err_data()
        if rel_err_data:
            return rel_err_data

        # check that this cluster is fully ready, otherwise put "configuring" in
        # peer rel data for requirers to show a blocked status until it's fully
        # ready (will receive a subsequent
        deployment_desc = self._peer_cm.deployment_desc()
        try:
            secrets = self._charm.secrets
            return PeerClusterRelData(
                cluster_name=deployment_desc.config.cluster_name,
                cm_nodes=self._fetch_local_cm_nodes(),
                credentials=PeerClusterRelDataCredentials(
                    admin_username="admin",
                    admin_password=secrets.get(ADMIN_PW),
                    admin_password_hash=secrets.get(ADMIN_PW_HASH),
                    admin_tls=secrets.get_object(Scope.APP, CertType.APP_ADMIN.val),
                ),
            )
        except OpenSearchHttpError as e:
            logger.exception(e)
            return PeerClusterRelErrorData(
                cluster_name=deployment_desc.config.cluster_name,
                should_sever_relation=False,
                should_wait=True,
                blocked_message=f"Could not fetch nodes in related {deployment_desc.typ} sub-cluster.",
            )

    def _rel_err_data(self) -> Optional[PeerClusterRelErrorData]:
        """Build error peer relation data object."""
        # TODO differentiate between the main and failover cluster manager ???
        deployment_desc = self._peer_cm.deployment_desc()

        should_sever_relation = False
        should_wait = True
        blocked_msg = None
        message_suffix = f"in related {deployment_desc.typ} sub-cluster."

        if not self._peer_cm.deployment_desc():
            blocked_msg = "Related sub-cluster not configured yet."
        elif self._peer_cm.deployment_desc().typ == DeploymentType.OTHER:
            should_sever_relation = True
            should_wait = False
            blocked_msg = "Related to non 'main/failover'-cluster-manager sub-cluster."
        elif not self._charm.is_admin_user_configured():
            blocked_msg = f"Admin user not fully configured {message_suffix}"
        elif not self._charm.is_tls_full_configured_in_cluster():
            blocked_msg = f"TLS not fully configured {message_suffix}"
        elif not self._charm.peers_data.get(Scope.APP, "security_index_initialised", False):
            blocked_msg = f"Security index not initialized {message_suffix}"
        else:
            try:
                local_cms = self._fetch_local_cm_nodes()
                if not local_cms:
                    blocked_msg = f"No reported cluster_manager eligible nodes {message_suffix}"
            except OpenSearchHttpError as e:
                logger.exception(e)
                blocked_msg = f"Could not fetch nodes {message_suffix}"

        if not blocked_msg:
            return None

        return PeerClusterRelErrorData(
            cluster_name=deployment_desc.config.cluster_name if deployment_desc else None,
            should_sever_relation=should_sever_relation,
            should_wait=should_wait,
            blocked_message=blocked_msg,
        )

    def _fetch_local_cm_nodes(self) -> List[Node]:
        """Fetch the cluster_manager eligible node IPs in the current cluster."""
        nodes = ClusterTopology.nodes(
            self._opensearch,
            use_localhost=self._opensearch.is_node_up(),
            hosts=self._charm.alt_hosts,
        )
        return [
            node
            for node in nodes
            if node.is_cm_eligible() and node.app_name == self._charm.app.name
        ]


class OpenSearchPeerClusterRequirer(Object):
    """Peer cluster relation requirer class."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, PeerClusterRelationName)

        self._charm = charm

        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_joined, self._on_peer_cluster_relation_joined
        )
        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_changed, self._on_peer_cluster_relation_changed
        )
        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_departed, self._on_peer_cluster_relation_departed,
        )

    def _on_peer_cluster_relation_joined(self, event: RelationJoinedEvent):
        pass

    def _on_peer_cluster_relation_changed(self, event: RelationChangedEvent):
        if not self._charm.unit.is_leader():
            return

        data = event.relation.data.get(event.app)
        if not data:
            return

        error_data = self._charm.peers_data.get_object("error_data")
        if error_data:
            error_data = PeerClusterRelErrorData.from_dict(error_data)
            self._charm.status.set(BlockedStatus(error_data.blocked_message), app=True)
            return

        # todo: compare TLS CA ---- Store APP Admin CA from peer rel !!!!!

        deployment_desc = self._charm.opensearch_peer_cm.deployment_desc()
        if not deployment_desc:
            event.defer()
            return

        data = PeerClusterRelData.from_dict(self._charm.peers_data.get_object("data"))

        # set admin credentials
        self._charm.secrets.put(Scope.APP, ADMIN_PW, data.credentials.admin_password)
        self._charm.secrets.put(Scope.APP, ADMIN_PW_HASH, data.credentials.admin_password_hash)
        self._charm.secrets.put(Scope.APP, CertType.APP_ADMIN.val, data.credentials.admin_tls)

        # store the app admin TLS resources
        self._charm.store_tls_resources(CertType.APP_ADMIN, data.credentials.admin_tls)

        # set user and security_index initialized flags
        self._charm.peers_data.put("admin_user_initialized", True)
        self._charm.peers_data.put("security_index_initialised", True)

        # check if ready
        if not self._charm.is_tls_fully_configured():
            event.defer()
            return

        # compare CAs
        unit_transport_ca_cert = self._charm.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val
        )["ca-cert"]
        if unit_transport_ca_cert != data.credentials.admin_tls["ca-cert"]:
            self._charm.status.set(BlockedStatus("CA certificate mismatch between clusters."))
            return

        # recompute the deployment desc
        self._charm.opensearch_peer_cm.run_with_relation_data(data)

    def _on_peer_cluster_relation_departed(self, event: RelationDepartedEvent):
        # this is where sub-clusters configured to auto-generated should probably recompute
        pass


    # TODO: implement logic of failover cluster
