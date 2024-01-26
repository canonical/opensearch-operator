# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Peer clusters relation related classes for OpenSearch."""
import json
import logging
from typing import TYPE_CHECKING, List, Optional, Union, Any, Dict, Tuple, MutableMapping

from tenacity import Retrying, stop_after_attempt, wait_fixed, RetryError

from charms.opensearch.v0.constants_charm import PeerClusterRelationName, PeerClusterManagerRelationName, \
    TLSRelationMissing, TLSNotFullyConfigured
from charms.opensearch.v0.constants_secrets import ADMIN_PW, ADMIN_PW_HASH
from charms.opensearch.v0.constants_tls import CertType, TLS_RELATION
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.models import (
    DeploymentType,
    PeerClusterRelData,
    PeerClusterRelDataCredentials,
    PeerClusterRelErrorData, Node,
)
from charms.opensearch.v0.opensearch_exceptions import OpenSearchError, OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import (
    BlockedStatus,
    EventBase,
    Object,
    RelationChangedEvent,
    RelationDepartedEvent,
    RelationEvent,
    RelationJoinedEvent,
    WaitingStatus,
)

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


class OpenSearchPeerClusterRelation(Object):

    def __init__(self, charm: "OpenSearchBaseCharm", relation_name: str):
        super().__init__(charm, relation_name)
        self.relation_name = relation_name
        self.charm = charm
        self.peer_cm = charm.opensearch_peer_cm

    def get_from_rel_data(
        self, key: str, rel_id: int = None, rel_app: bool = False
    ) -> Optional[str]:
        """Fetch relation data by key from relation id (from an int or relation event)."""
        if not rel_id:
            raise ValueError("Relation id must be provided as arguments.")

        relation = self.charm.model.get_relation(self.relation_name, relation_id=rel_id)
        if relation:
            return relation.data[relation.app if rel_app else self.charm.app].get(key)

        return None

    def get_obj_from_rel_data(
        self, key: str, rel_id: int = None, rel_app: bool = False
    ) -> Optional[Dict[Any, Any]]:
        """Get object from peer cluster relation data."""
        data = self.get_from_rel_data(key, rel_id=rel_id, rel_app=rel_app)
        if not data:
            return None

        return json.loads(data)

    def put_in_rel_data(
        self, data: Dict[str, Any], rel_id: Optional[int] = None
    ) -> None:
        """Put object in peer cluster rel data."""
        if not rel_id:
            raise ValueError("Relation id must be provided as arguments.")

        relation = self.charm.model.get_relation(self.relation_name, relation_id=rel_id)
        if relation:
            relation.data[self.charm.app].update(data)

    def delete_from_rel_data(
        self, key: str, event: Optional[RelationEvent] = None, rel_id: Optional[int] = None
    ) -> None:
        """Delete from peer cluster relation data by key."""
        if not event and not rel_id:
            raise ValueError("Relation Event or relation id must be provided as arguments.")

        relation = self.charm.model.get_relation(
            self.relation_name, relation_id=rel_id if rel_id else event.relation.id
        )
        if relation:
            relation.data[self.charm.app].pop(key, None)


class OpenSearchPeerClusterProvider(OpenSearchPeerClusterRelation):
    """Peer cluster relation provider class."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, PeerClusterManagerRelationName)
        self._opensearch = charm.opensearch

        self.framework.observe(
            charm.on[self.relation_name].relation_joined, self._on_peer_cluster_relation_joined
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_changed, self._on_peer_cluster_relation_changed
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_departed, self._on_peer_cluster_relation_departed,
        )
        # todo how to differentiate between current cluster leaving
        # the relation vs sub-cluster leaving

    def _on_peer_cluster_relation_joined(self, event: RelationJoinedEvent):
        """Event received by all units in main/failover CM when new sub-cluster joins the relation."""
        logger.debug(f"\n\n\nPROVIDER: _on_peer_cluster_relation_joined: {self.charm.unit_name}"
                     f" ---> {event.unit.name} \n\n")
        self.refresh_relation_data(event)
        # self.charm.trigger_leader_peer_rel_changed()

    def _on_peer_cluster_relation_changed(self, event: RelationChangedEvent):
        """Event received by all units in sub-cluster when a new sub-cluster joins the relation."""
        # self.charm.trigger_leader_peer_rel_changed()
        if not self.charm.unit.is_leader():
            return

        deployment_desc = self.peer_cm.deployment_desc()
        if not deployment_desc:
            event.defer()
            return

        if deployment_desc.typ == DeploymentType.MAIN_CLUSTER_MANAGER:
            return

        data = event.relation.data.get(event.app)   # TODO: this one empty
        if not data:
            logger.debug(f"\n\nPROVIDER: _on_peer_cluster_relation_changed: not data leaving...\n\n")
            return

        target_relation_ids = [
            rel.id for rel in self.charm.model.relations[self.relation_name]
        ]

        # fetch emitting app planned units and broadcast
        planned_units = json.loads(data.get("planned_units"))
        self._put_planned_units(planned_units["app"], planned_units["count"], target_relation_ids)

        # todo: store the rel id in the main cluster peer rel databag and upon re-election, clone all rel data
        candidate_failover_cm_app = data.get("candidate-failover-cluster-manager-app")
        if not candidate_failover_cm_app:
            self.refresh_relation_data(event)
            return

        registered_cluster_managers = (
            self.get_obj_from_rel_data("peer-cluster-managers", rel_id=int(target_relation_ids[0])) or {}
        )
        if registered_cluster_managers.get("failover-cluster-manager-app"):
            logger.info("A failover cluster manager has already been registered.")
            self.refresh_relation_data(event)
            return

        for rel_id in target_relation_ids:
            registered_cluster_managers.update({
                "failover-cluster-manager-app": candidate_failover_cm_app,
                "failover-cluster-manager-rel-id": event.relation.id,
            })
            self.put_in_rel_data(
                data={"peer-cluster-managers": json.dumps(registered_cluster_managers)}, rel_id=rel_id
            )

    def refresh_relation_data(self, event: EventBase):
        """Refresh the peer cluster rel data (new cm node, admin password change etc.)."""
        if not self.charm.unit.is_leader():
            return

        peer_rel_data_key = "data"

        rel_data = self._rel_data()

        logger.debug(f"PROVIDER: refresh_relation_data: {self.charm.unit_name} ---> \n\n{rel_data.to_dict()} \n\n")

        all_relation_ids = [
            rel.id for rel in self.charm.model.relations[self.relation_name]
        ]

        # store the main/failover-cm planned units count
        self._put_planned_units(
            self.charm.app.name, self.charm.app.planned_units(), all_relation_ids
        )

        if self.charm.opensearch_peer_cm.deployment_desc().typ != DeploymentType.MAIN_CLUSTER_MANAGER:
            logger.debug(f"\nPROVIDER!!! FAILOVER CLUSTER")
            for a in self.charm.model.relations[self.relation_name]:
                logger.debug(f"\nPROVIDER -- RELATED APP: {a.app.name} VS {self.charm.app.name}: {[(u.app.name, u.name) for u in a.units]}")

        logger.debug(f"\nPROVIDER: RELATED APP: {all_relation_ids}")

        deployment_desc = self.charm.opensearch_peer_cm.deployment_desc()
        cluster_type = "main" if deployment_desc.typ == DeploymentType.MAIN_CLUSTER_MANAGER else "failover"

        # save the managers of this fleet
        should_defer = False
        for rel_id in all_relation_ids:
            logger.debug(f"\nPROVIDER -- RELATED APP: {all_relation_ids}")
            cluster_managers = self.get_obj_from_rel_data("peer-cluster-managers", rel_id=rel_id) or {}
            cluster_managers.update({
                f"{cluster_type}-cluster-manager-app": self.charm.app.name,
                f"{cluster_type}-cluster-manager-rel-id": rel_id,
            })
            self.put_in_rel_data(data={"peer-cluster-managers": json.dumps(cluster_managers)}, rel_id=rel_id)

            if isinstance(rel_data, PeerClusterRelErrorData):
                self.delete_from_rel_data("error_data", rel_id=rel_id)
                peer_rel_data_key = "error_data"
                if rel_data.should_wait:
                    should_defer = True
            else:
                # for rel_id in target_relation_ids:
                self.delete_from_rel_data("error_data", rel_id=rel_id)
            self.put_in_rel_data(
                data={peer_rel_data_key: json.dumps(rel_data.to_dict())}, rel_id=rel_id
            )

        if should_defer:
            event.defer()

    def _put_planned_units(self, app: str, count: int, target_relation_ids: List[int]):
        """Save in the peer cluster rel data the planned units count per app."""
        cluster_fleet_planned_units = self.charm.peers_data.get_object(
            Scope.APP, "cluster_fleet_planned_units"
        ) or {}

        cluster_fleet_planned_units.update({app: count})
        cluster_fleet_planned_units.update({self.charm.app.name: self.charm.app.planned_units()})

        for rel_id in target_relation_ids:
            self.put_in_rel_data(
                data={"planned_units": json.dumps(cluster_fleet_planned_units)}, rel_id=rel_id
            )

        self.charm.peers_data.put_object(
            Scope.APP, "cluster_fleet_planned_units", cluster_fleet_planned_units
        )

    def _on_peer_cluster_relation_departed(self, event: RelationDepartedEvent):
        """Event received by all units in sub-cluster when a sub-cluster leaves the relation."""
        logger.info(f"\n\nPROVIDER: _on_peer_cluster_relation_departed:\n{event.unit.name}\n\n\n")

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
        deployment_desc = self.peer_cm.deployment_desc()
        try:
            secrets = self.charm.secrets
            return PeerClusterRelData(
                cluster_name=deployment_desc.config.cluster_name,
                cm_nodes=self._fetch_local_cm_nodes(),
                credentials=PeerClusterRelDataCredentials(
                    admin_username="admin",
                    admin_password=secrets.get(Scope.APP, ADMIN_PW),
                    admin_password_hash=secrets.get(Scope.APP, ADMIN_PW_HASH),
                    admin_tls=secrets.get_object(Scope.APP, CertType.APP_ADMIN.val),
                ),
                deployment_desc=deployment_desc,
            )
        except OpenSearchHttpError as e:
            logger.exception(e)
            return PeerClusterRelErrorData(
                cluster_name=deployment_desc.config.cluster_name,
                should_sever_relation=False,
                should_wait=True,
                blocked_message=f"Could not fetch nodes in related {deployment_desc.typ} sub-cluster.",
                deployment_desc=deployment_desc,
            )

    def _rel_err_data(self) -> Optional[PeerClusterRelErrorData]:
        """Build error peer relation data object."""
        # TODO differentiate between the main and failover cluster manager ???
        deployment_desc = self.peer_cm.deployment_desc()

        peer_cms = self.charm.peers_data.get_object(Scope.APP, "peer-cluster-managers") or {}
        failover_cm_app = peer_cms.get("failover-cluster-manager-app")

        should_sever_relation = False
        should_wait = True
        blocked_msg = None
        message_suffix = f"in related {deployment_desc.typ} peer-cluster"

        if not deployment_desc:
            blocked_msg = "Related sub-cluster not configured yet."
        elif deployment_desc.typ == DeploymentType.OTHER:
            should_sever_relation = True
            should_wait = False
            blocked_msg = "Related to non 'main/failover'-cluster-manager peer-cluster."
        elif failover_cm_app and failover_cm_app != self.charm.app.name:
            blocked_msg = f"Cannot have 2 'failover'-cluster-managers. Relate to the existing failover cluster."
        elif not self.charm.is_admin_user_configured():
            blocked_msg = f"Admin user not fully configured {message_suffix}."
        elif not self.charm.is_tls_full_configured_in_cluster():
            blocked_msg = f"TLS not fully configured {message_suffix}."
        elif not self.charm.peers_data.get(Scope.APP, "security_index_initialised", False):
            blocked_msg = f"Security index not initialized {message_suffix}."
        elif not self.charm.is_every_unit_marked_as_started():
            blocked_msg = f"Waiting for every unit {message_suffix} to have started."
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
            deployment_desc=deployment_desc,
        )

    def _fetch_local_cm_nodes(self) -> List[Node]:
        """Fetch the cluster_manager eligible node IPs in the current cluster."""
        nodes = ClusterTopology.nodes(
            self._opensearch,
            use_localhost=self._opensearch.is_node_up(),
            hosts=self.charm.alt_hosts,
        )
        return [
            node
            for node in nodes
            if node.is_cm_eligible() and node.app_name == self.charm.app.name
        ]


class OpenSearchPeerClusterRequirer(OpenSearchPeerClusterRelation):
    """Peer cluster relation requirer class."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, PeerClusterRelationName)

        self.framework.observe(
            charm.on[self.relation_name].relation_joined, self._on_peer_cluster_relation_joined
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_changed, self._on_peer_cluster_relation_changed
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_departed, self._on_peer_cluster_relation_departed,
        )

    def _on_peer_cluster_relation_joined(self, event: RelationJoinedEvent):
        logger.debug(f"\n\n\nREQUIRER: _on_peer_cluster_relation_joined: {self.charm.unit_name} "
                     f"---> {event.unit.name} \n\n")
        # self.charm.trigger_leader_peer_rel_changed()
        pass

    def _on_peer_cluster_relation_changed(self, event: RelationChangedEvent):

        def set_err_status(error: Optional[Dict[str, Any]]) -> bool:
            if not error:
                return False

            error = PeerClusterRelErrorData.from_dict(error)
            err_message = error.blocked_message
            self.charm.status.set(
                WaitingStatus(err_message) if error.should_wait else BlockedStatus(err_message),
                app=True,
            )
            logger.error(f"\n\nREQUIRER: error: {error.to_dict()}\n\n\n\n")
            return True

        # logger.debug(f"\n\n\nREQUIRER: _on_peer_cluster_relation_changed: {self.charm.unit_name} "
        #              f"---> rel id: {event.relation.id} "
        #              f"---> app: event/{event.app.name} -- charm/{self.charm.app.name} "
        #              f"\n---> {event.relation.data.get(event.app)} ---")
        # self.charm.trigger_leader_peer_rel_changed()

        if not self.charm.unit.is_leader():
            logger.debug(f"REQUIRER _on_peer_cluster_relation_changed: not leader leaving...\n\n")
            return

        logger.debug("\n\n\n\n\n\n -------------------------------------------\n\t--- REQUIRER")

        # register in the 'main/failover'-CMs / save the number of planned units of the current app
        self._put_planned_units(event)

        data = event.relation.data.get(event.app)   # TODO: this one empty
        if not data:
            logger.debug(f"REQUIRER: _on_peer_cluster_relation_changed: not data leaving...")
            logger.debug(f"\n------------------------------------------------\n\n\n")
            return

        cm_relations = dict([(rel.id, rel.app.name) for rel in self.model.relations[self.relation_name]])
        # logger.debug(f"\n\n\nREQUIRER -- YOOOO --- \nRELATIONS: {cm_relations}")

        # fetch main and failover clusters relations ids if any
        main_cm_rel_id, main_cm_app, failover_cm_rel_id, failover_cm_app = self._get_related_cluster_manager_ids(
            event, data, cm_relations
        )

        # logger.debug(f"\n\n\nREQUIRER -- YOOOO --- \nRELATIONS: "
        #              f"Event: {event.relation.id}\n"
        #              f"main_cm: {main_cm_rel_id}: {main_cm_app}\n"
        #              f"failover_cm: {failover_cm_rel_id}: {failover_cm_app}")

        # check for errors in alternate relation (in case related to main and failover)
        # so we don't keep overriding the statuses
        if main_cm_rel_id != -1:
            error_data = self.get_obj_from_rel_data("error_data", rel_id=main_cm_rel_id, rel_app=True)
            logger.debug(f"REQUIRER -- MAIN CM Error: {error_data}")
            if set_err_status(error_data):
                logger.debug(f"REQUIRER --- ERROR: Previously Existing MAIN CM error data: {error_data}")
                logger.debug(f"\n------------------------------------------------\n\n\n")
                return

        if "error_data" in data:
            logger.debug(f"REQUIRER -- Error in DATA: {data['error_data']}")
            set_err_status(json.loads(data["error_data"]))
            return
            # todo: set errors in the deployment desc -- run_with relation data, what about
            #  cleanup after they're solved??
            # todo: handle the cleanup of these in peer cluster relation broken / (departed
            #  with planned units 0 ??)

        if failover_cm_rel_id != -1:
            error_data = self.get_obj_from_rel_data("error_data", rel_id=failover_cm_rel_id, rel_app=True)  # TODO: pass
            logger.debug(f"REQUIRER -- FAILOVER CM Error: {error_data}")
            if set_err_status(error_data):
                logger.debug(f"REQUIRER --- ERROR: Previously Existing FAILOVER CM error data: {error_data}")
                logger.debug(f"\n------------------------------------------------\n\n\n")
                return

        if "data" not in data:
            return

        deployment_desc = self.charm.opensearch_peer_cm.deployment_desc()
        if not deployment_desc:
            logger.debug(f"REQUIRER: _on_peer_cluster_relation_changed: not deployment_desc "
                         f"leaving + deferring...\n\n")
            event.defer()
            logger.debug(f"\n------------------------------------------------\n\n\n")
            return

        data = PeerClusterRelData.from_str(data["data"])
        tmp_d = data.to_dict().copy()
        if "credentials" in tmp_d:
            if tmp_d["credentials"].get("admin_tls"):
                tmp_d["credentials"]["admin_tls"] = {}
        logger.debug(f"_on_peer_cluster_relation_changed --- DATA... ")#{tmp_d}")

        # handle error states that can only be figured out from the requirer side
        error_data = self._rel_err_data(data, event.relation.id)
        if set_err_status(error_data.to_dict() if error_data else None):
            # todo: set errors in the deployment desc -- run_with relation data, what about
            #  cleanup after they're solved??
            # todo: handle the cleanup of these in peer cluster relation broken / (departed
            #  with planned units 0 ??)
            logger.debug(f"\n------------------------------------------------\n\n\n")
            event.defer()
            return

        # this means it's a previous "main cluster manager" that was unrelated then re-related
        if deployment_desc.typ == DeploymentType.MAIN_CLUSTER_MANAGER:
            logger.debug(f"REQUIRER: DEMOTING")
            self.charm.opensearch_peer_cm.demote_to_failover_cluster_manager()

        # broadcast that this cluster is a failover candidate, and let the main CM elect it or not
        if deployment_desc.typ == DeploymentType.FAILOVER_CLUSTER_MANAGER:
            self.put_in_rel_data(
                data={"candidate-failover-cluster-manager-app": self.charm.app.name}, rel_id=event.relation.id
            )

        # set admin credentials
        if self.charm.secrets.get(Scope.APP, ADMIN_PW) != data.credentials.admin_password:  # todo remove condition
            self.charm.secrets.put(Scope.APP, ADMIN_PW, data.credentials.admin_password)
            self.charm.secrets.put(Scope.APP, ADMIN_PW_HASH, data.credentials.admin_password_hash)

            # set user and security_index initialized flags  -- TODO: put back after secrets.store
            self.charm.peers_data.put(Scope.APP, "admin_user_initialized", True)
            self.charm.peers_data.put(Scope.APP, "security_index_initialised", True)

        if self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) != data.credentials.admin_tls:  # todo remove condition
            self.charm.secrets.put_object(Scope.APP, CertType.APP_ADMIN.val, data.credentials.admin_tls)

            # store the app admin TLS resources if not stored
            self.charm.store_tls_resources(CertType.APP_ADMIN, data.credentials.admin_tls)

        store = {
            "main-cluster-manager-rel-id": main_cm_rel_id,
            "main-cluster-manager-app": main_cm_app,
            "failover-cluster-manager-rel-id": failover_cm_rel_id,
            "failover-cluster-manager-app": failover_cm_app,
        }
        if self.charm.peers_data.get(Scope.APP, "peer-cluster-managers") != store:
            # register main and failover cm app names if any, another benefit of the following is
            # to trigger a peer_rel_changed event on each units to populate their unicast_hosts.txt
            # with new CMs / delete old ones
            self.charm.peers_data.put_object(
                scope=Scope.APP,
                key="peer-cluster-managers",
                value={
                    "main-cluster-manager-rel-id": main_cm_rel_id,
                    "main-cluster-manager-app": main_cm_app,
                    "failover-cluster-manager-rel-id": failover_cm_rel_id,
                    "failover-cluster-manager-app": failover_cm_app,
                },
            )

        logger.debug(f"REQUIRER: _on_peer_cluster_relation_changed: STORED EVERYTHING NEEDED...")

        # check if ready
        if not self.charm.is_tls_fully_configured():
            if not self.charm.model.get_relation(TLS_RELATION):
                self.charm.status.set(BlockedStatus(TLSRelationMissing), app=True)
                logger.debug(f"REQUIRER: _on_peer_cluster_relation_changed: TLS not related -- deferring...\n\n")
            else:
                self.charm.status.set(BlockedStatus(TLSNotFullyConfigured), app=True)
                logger.debug(f"REQUIRER: _on_peer_cluster_relation_changed: TLS not STORED fully -- deferring...\n\n")
            event.defer()
            logger.debug(f"\n------------------------------------------------\n\n\n")
            return

        # compare CAs
        unit_transport_ca_cert = self.charm.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val
        )["ca-cert"]
        if unit_transport_ca_cert != data.credentials.admin_tls["ca-cert"]:
            self.charm.status.set(BlockedStatus("CA certificate mismatch between clusters."))
            logger.debug(f"\n------------------------------------------------\n\n\n")
            return

        # aggregate all CMs (main + failover if any)
        if main_cm_rel_id > -1 and failover_cm_rel_id > -1:
            main_cms = (self.get_obj_from_rel_data(key="data", rel_id=main_cm_rel_id, rel_app=True) or {})
            if main_cms:
                main_cms = PeerClusterRelData.from_dict(main_cms).cm_nodes

            failover_cms = self.get_obj_from_rel_data(key="data", rel_id=failover_cm_rel_id, rel_app=True) or {}
            if failover_cms:
                failover_cms = PeerClusterRelData.from_dict(failover_cms).cm_nodes

            for cm_node in main_cms + failover_cms:
                if cm_node not in data.cm_nodes:
                    data.cm_nodes.append(cm_node)

        # recompute the deployment desc
        self.charm.opensearch_peer_cm.run_with_relation_data(data)
        logger.debug(f"\n------------------------------------------------\n\n\n")

    def _get_related_cluster_manager_ids(
        self, event: RelationChangedEvent, data: MutableMapping[str, str], cm_relations: Dict[int, str]
    ) -> Tuple[int, str, int, str]:
        """Fetch related cluster manager IDs and App names."""
        peer_cms = self.get_obj_from_rel_data(
            key="peer-cluster-managers", rel_id=event.relation.id, rel_app=True
        ) or {}
        for rel_id, rel_app_name in cm_relations.items():
            logger.debug(f"RELATION: {rel_id}:{rel_app_name}")
            peer_cms.update(
                self.get_obj_from_rel_data(
                    key="peer-cluster-managers", rel_id=rel_id, rel_app=True
                ) or {}
            )
            logger.debug(f"\nRELATION: {rel_id}:{rel_app_name}\n\t{peer_cms}")

        if not peer_cms:
            peer_cms = json.loads(data["peer-cluster-managers"])
            logger.debug(f"\nRELATION: peer_cms: {peer_cms}")

        return (
            peer_cms.get("main-cluster-manager-rel-id", -1),
            peer_cms.get("main-cluster-manager-app"),
            peer_cms.get("failover-cluster-manager-rel-id", -1),
            peer_cms.get("failover-cluster-manager-app"),
        )

    def _put_planned_units(self, event: RelationEvent):
        """Report self planned units and store the fleet's on the peer data bag."""
        # register the number of planned units in the current cluster, to be communicated to the main-cm
        self.put_in_rel_data(
            data={
                "planned_units": json.dumps({
                    "app": self.charm.app.name,
                    "count": self.charm.app.planned_units(),
                }),
            },
            rel_id=event.relation.id,
        )

        # self in the current app's peer databag
        cluster_fleet_planned_units = self.get_obj_from_rel_data("planned_units", rel_id=event.relation.id, rel_app=True) or {}
        cluster_fleet_planned_units.update({self.charm.app.name: self.charm.app.planned_units()})

        self.charm.peers_data.put_object(Scope.APP, "cluster_fleet_planned_units", cluster_fleet_planned_units)

    def _on_peer_cluster_relation_departed(self, event: RelationDepartedEvent):
        """Handle when 'main/failover'-CMs leave the relation (app or relation removal)."""
        # this is where sub-clusters configured to auto-generated should probably recompute
        # self.charm.trigger_leader_peer_rel_changed()
        if not self.charm.unit.is_leader():  # To run the cleanup logic just once.
            return

        logger.debug(f"\n\n\n_on_peer_cluster_relation_departed: {event.relation.id}")

        peer_cm_conf = self.charm.peers_data.get_object(Scope.APP, "peer-cluster-managers")

        logger.debug(f"\n\n\n_on_peer_cluster_relation_departed: \n{peer_cm_conf}\n\n")

        main_cm_rel_id = peer_cm_conf.get("main-cluster-manager-rel-id")
        main_cm_app_name = peer_cm_conf.get("main-cluster-manager-app")
        failover_cm_rel_id = peer_cm_conf.get("failover-cluster-manager-rel-id")
        failover_cm_app_name = peer_cm_conf.get("failover-cluster-manager-app")

        # a cluster of type "other" is departing, we can safely ignore.
        if event.relation.id not in [main_cm_rel_id, failover_cm_rel_id]:
            return

        # fetch relation info
        goal_state = self.model._backend._run("goal-state", return_output=True, use_json=True)
        rel_info = goal_state["relations"][self.relation_name]

        # check the cluster who triggered this hook
        event_src_cluster_type = "main" if event.relation.id == main_cm_rel_id else "failover"

        deployment_desc = self.charm.opensearch_peer_cm.deployment_desc()
        if deployment_desc.typ == DeploymentType.OTHER:
            peer_cm_conf.pop(f"{event_src_cluster_type}-cluster-manager-rel-id", None)
            peer_cm_conf.pop(f"{event_src_cluster_type}-cluster-manager-app", None)
            self.charm.peers_data.put(Scope.APP, "peer-clusters-managers", peer_cm_conf)
            return

        # check dying units
        dying_units = [
            unit_data["status"] == "dying"
            for unit, unit_data in rel_info.items()
            if unit != self.relation_name
        ]

        # check if app removal
        is_app_removal = all(dying_units)
        is_scale_down = any(dying_units)
        is_rel_broken = not is_app_removal and not is_scale_down

        # handle scale-down at the charm level storage detaching, or??
        if is_scale_down:
            return

        # fetch cluster manager nodes across all peer clusters
        full_cms = self._cm_nodes()
        main_cms = [cm for cm in full_cms if cm.app_name == main_cm_app_name]
        non_main_cms = [cm for cm in full_cms if cm.app_name != main_cm_app_name]

        # the main cluster manager is the one being removed
        if event_src_cluster_type == "main":
            if not failover_cm_app_name:
                self.charm.status.set(
                    BlockedStatus("Main-cluster-manager removed, and no failover cluster related.")
                )
                self.charm.peers_data.delete(Scope.APP, "peer-cluster-managers")
                return

            if failover_cm_app_name != self.charm.app.name:
                peer_cm_conf.pop("main-cluster-manager-app", None)
                peer_cm_conf.pop("main-cluster-manager-rel-id", None)
                self.charm.peers_data.put(Scope.APP, "peer-clusters-managers", peer_cm_conf)
                return

            # current cluster is failover
            # TODO: copy and store all data previously in main CM
            self.charm.opensearch_peer_cm.promote_to_main_cluster_manager()

            # ensuring quorum
            if len(non_main_cms) % 2 == 0:
                message = "Scale-up this application by an odd number of units{} to ensure quorum."
                if is_rel_broken and len(main_cms) % 2 == 1:
                    message = message.format(f"and scale-'down/up' {main_cm_app_name} by 1 unit.")

                self.charm.status.set(message)

            # update peer rel data of current unit
            self.charm.peers_data.put_object(
                scope=Scope.APP,
                key="peer-cluster-managers",
                value={
                    "main-cluster-manager-app": peer_cm_conf.get("failover-cluster-manager-app"),
                    "main-cluster-manager-rel-id": peer_cm_conf.get("failover-cluster-manager-rel-id"),
                }
            )

            # broadcast the new conf to all related units
            target_rel_ids = [rel.id for rel in self.charm.model.relations[self.relation_name]]

            for rel_id in target_rel_ids:
                peer_cm_conf.update({
                    "main-cluster-manager-app": self.charm.app.name,
                    "main-cluster-manager-rel-id": rel_id,
                })
                self.put_in_rel_data(data={"peer-cluster-managers": json.dumps(peer_cm_conf)}, rel_id=event.relation.id)
            return

        # the following indicates that we are removing a failover cluster
        peer_cm_conf.pop("failover-cluster-manager-app", None)
        peer_cm_conf.pop("failover-cluster-manager-rel-id", None)
        self.charm.peers_data.put(Scope.APP, "peer-clusters-managers", peer_cm_conf)

        # broadcast the new conf to all related units
        if main_cm_app_name == self.charm.app.name:
            self.charm.peers_data.put_object(
                scope=Scope.APP,
                key="peer-cluster-managers",
                value={
                    "main-cluster-manager-app": peer_cm_conf.get("main-cluster-manager-app"),
                    "main-cluster-manager-rel-id": peer_cm_conf.get("main-cluster-manager-rel-id"),
                },
            )

    def _cm_nodes(self) -> Optional[List[Node]]:
        """Test if current setup can have a quorum."""
        try:
            for attempt in Retrying(stop=stop_after_attempt(3), wait=wait_fixed(0.5)):
                with attempt:
                    nodes = ClusterTopology.nodes(
                        self.charm.opensearch,
                        use_localhost=self.charm.opensearch.is_node_up(),
                        hosts=self.charm.alt_hosts,
                    )
                    return [node for node in nodes if node.is_cm_eligible()]
        except RetryError:
            return None

    def _rel_err_data(
        self, peer_cluster_rel_data: PeerClusterRelData, event_rel_id: int
    ) -> Optional[PeerClusterRelErrorData]:
        """Build error peer relation data object."""
        deployment_desc = self.peer_cm.deployment_desc()

        logger.debug(f"_rel_err_data - event_rel_id: {event_rel_id}")

        peer_cm_conf = self.charm.peers_data.get_object(Scope.APP, "peer-cluster-managers")
        if not peer_cm_conf:
            return None

        main_cm_rel_id = peer_cm_conf.get("main-cluster-manager-rel-id", -1)
        failover_cm_rel_id = peer_cm_conf.get("failover-cluster-manager-rel-id", -1)

        logger.debug(f"_rel_err_data - event_rel_id: {event_rel_id} -- "
                     f"[main_cm_rel_id: {main_cm_rel_id}, failover_cm_rel_id: {failover_cm_rel_id}]")

        should_sever_relation = False
        should_wait = True
        blocked_msg = None

        if deployment_desc.typ == DeploymentType.MAIN_CLUSTER_MANAGER:
            blocked_msg = "Main cluster-manager cannot be requirer of relation."
            should_wait = False
            should_sever_relation = True
        elif event_rel_id not in [main_cm_rel_id, failover_cm_rel_id]:
            blocked_msg = ("A cluster can only be related to 1 main-cluster and 1 "
                           "failover-cluster managers at most.")
            should_wait = False
            should_sever_relation = True

        if not blocked_msg:
            return None

        return PeerClusterRelErrorData(
            cluster_name=peer_cluster_rel_data.cluster_name,
            should_sever_relation=should_sever_relation,
            should_wait=should_wait,
            blocked_message=blocked_msg,
            deployment_desc=deployment_desc,
        )
