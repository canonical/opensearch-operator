# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Peer clusters relation related classes for OpenSearch."""
import json
import logging
from typing import TYPE_CHECKING, List, Optional, Union, Any, Dict, MutableMapping

from tenacity import Retrying, stop_after_attempt, wait_fixed, RetryError

from charms.opensearch.v0.constants_charm import (
    PeerClusterOrchestratorRelationName,
    PeerClusterRelationName,
    TLSNotFullyConfigured,
    TLSRelationMissing,
)
from charms.opensearch.v0.constants_secrets import ADMIN_PW, ADMIN_PW_HASH
from charms.opensearch.v0.constants_tls import CertType, TLS_RELATION
from charms.opensearch.v0.helper_charm import RelDepartureReason, relation_departure_reason
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.models import (
    DeploymentType,
    Node,
    PeerClusterOrchestrators,
    PeerClusterRelData,
    PeerClusterRelDataCredentials,
    PeerClusterRelErrorData,
)
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import (
    BlockedStatus,
    EventBase,
    Object,
    Relation,
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


class OpenSearchPeerClusterRelation(Object):
    """Base class for Peer cluster relations."""

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

        relation = self.get_rel(rel_id=rel_id)
        if relation:
            return relation.data[relation.app if rel_app else self.charm.app].get(key)

        return None

    def get_obj_from_rel_data(
        self, key: str, rel_id: int = None, rel_app: bool = False
    ) -> Dict[Any, Any]:
        """Get object from peer cluster relation data."""
        data = self.get_from_rel_data(key, rel_id=rel_id, rel_app=rel_app) or {}
        return json.loads(data)

    def put_in_rel_data(
        self, data: Dict[str, Any], rel_id: Optional[int] = None
    ) -> None:
        """Put object in peer cluster rel data."""
        if not rel_id:
            raise ValueError("Relation id must be provided as arguments.")

        relation = self.get_rel(rel_id=rel_id)
        if relation:
            relation.data[self.charm.app].update(data)

    def delete_from_rel_data(
        self, key: str, event: Optional[RelationEvent] = None, rel_id: Optional[int] = None
    ) -> None:
        """Delete from peer cluster relation data by key."""
        if not event and not rel_id:
            raise ValueError("Relation Event or relation id must be provided as arguments.")

        relation = self.get_rel(rel_id=rel_id if rel_id else event.relation.id)
        if relation:
            relation.data[self.charm.app].pop(key, None)

    def get_rel(self, rel_id: Optional[int]) -> Optional[Relation]:
        """Retrieve the relation object assigned to this id."""
        return self.charm.model.get_relation(self.relation_name, relation_id=rel_id)


class OpenSearchPeerClusterProvider(OpenSearchPeerClusterRelation):
    """Peer cluster relation provider class."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, PeerClusterOrchestratorRelationName)
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

    def _on_peer_cluster_relation_joined(self, event: RelationJoinedEvent):
        """Received by all units in main/failover clusters when new sub-cluster joins the rel."""
        self.refresh_relation_data(event)

        # TODO: is the below still needed
        # self.charm.trigger_leader_peer_rel_changed()

    def _on_peer_cluster_relation_changed(self, event: RelationChangedEvent):
        """Event received by all units in sub-cluster when a new sub-cluster joins the relation."""
        # self.charm.trigger_leader_peer_rel_changed()
        if not self.charm.unit.is_leader():
            return

        if not (deployment_desc := self.peer_cm.deployment_desc()):
            event.defer()
            return

        if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            return

        if not (data := event.relation.data.get(event.app)):
            return

        target_relation_ids = [
            rel.id for rel in self.charm.model.relations[self.relation_name]
        ]

        # fetch emitting app planned units and broadcast
        self._put_planned_units(target_relation_ids)

        # todo: store the rel id in the main-orchestrator peer data, and clone all on promotion
        if not (candidate_failover_cm_app := data.get("candidate_failover_orchestrator_app")):
            self.refresh_relation_data(event)
            return

        orchestrators = PeerClusterOrchestrators.from_dict(
            self.charm.peers_data.get_object("orchestrators")
        )
        if orchestrators.failover_app:
            logger.info("A failover cluster orchestrator is already registered.")
            self.refresh_relation_data(event)
            return

        # no failover cluster was already registered, we do it
        orchestrators.failover_app = candidate_failover_cm_app
        orchestrators.failover_rel_id = event.relation.id

        self.charm.peers_data.put_object(Scope.APP, "orchestrators", orchestrators.to_dict())
        for rel_id in target_relation_ids:
            self.put_in_rel_data(
                data={"orchestrators": json.dumps(orchestrators.to_dict())}, rel_id=rel_id
            )

    def refresh_relation_data(self, event: EventBase):
        """Refresh the peer cluster rel data (new cm node, admin password change etc.)."""
        if not self.charm.unit.is_leader():
            return

        all_relation_ids = [
            rel.id for rel in self.charm.model.relations[self.relation_name]
        ]

        # compute the data that needs to be broadcast to all related clusters (success or error)
        rel_data = self._rel_data()

        # exit if current cluster should not have been considered a provider
        if self._notify_if_wrong_integration(rel_data, all_relation_ids):
            return

        # store the main/failover-cm planned units count
        self._put_planned_units(all_relation_ids)

        cluster_type = "main"
        if self.charm.opensearch_peer_cm.deployment_desc().typ == DeploymentType.FAILOVER_ORCHESTRATOR:
            cluster_type = "failover"

        peer_rel_data_key, should_defer = "data", False
        if isinstance(rel_data, PeerClusterRelErrorData):
            peer_rel_data_key, should_defer = "error_data", rel_data.should_wait

        # save the orchestrators of this fleet
        for rel_id in all_relation_ids:
            orchestrators = self.get_obj_from_rel_data("orchestrators", rel_id=rel_id)
            orchestrators.update({
                f"{cluster_type}_app": self.charm.app.name,
                f"{cluster_type}_rel_id": rel_id,
            })
            self.put_in_rel_data(data={"orchestrators": orchestrators}, rel_id=rel_id)

            # there is no error to broadcast - we clear any previously broadcasted error
            if isinstance(rel_data, PeerClusterRelData):
                self.delete_from_rel_data("error_data", rel_id=rel_id)

            self.put_in_rel_data(
                data={peer_rel_data_key: json.dumps(rel_data.to_dict())}, rel_id=rel_id
            )

        if should_defer:
            event.defer()

    def _notify_if_wrong_integration(
        self, rel_data: Union[PeerClusterRelData, PeerClusterRelErrorData], target_relation_ids: List[int]
    ) -> bool:
        """Check if relation is invalid and notify related sub-clusters."""
        if not isinstance(rel_data, PeerClusterRelErrorData):
            return False

        if not rel_data.should_sever_relation:
            return False

        for rel_id in target_relation_ids:
            self.put_in_rel_data(data={"error_data": rel_data.to_dict()}, rel_id=rel_id)

        return True

    def _put_planned_units(self, target_relation_ids: List[int]) -> None:
        """Save in the peer cluster rel data the planned units count per app."""
        cluster_fleet_planned_units = {self.charm.app.name: self.charm.app.planned_units()}
        for rel_id in target_relation_ids:
            app = self.get_rel(rel_id).app  # todo: need to ensure unicity of app name for cross models
            cluster_fleet_planned_units[app.name] = app.planned_units()

        for rel_id in target_relation_ids:
            self.put_in_rel_data(
                data={"cluster_fleet_planned_units": cluster_fleet_planned_units}, rel_id=rel_id
            )

        self.charm.peers_data.put_object(
            Scope.APP, "cluster_fleet_planned_units", cluster_fleet_planned_units
        )

    def _on_peer_cluster_relation_departed(self, _: RelationDepartedEvent) -> None:
        """Event received by all units in sub-cluster when a sub-cluster leaves the relation."""
        # we need to update the fleet planned units
        target_relation_ids = [
            rel.id for rel in self.charm.model.relations[self.relation_name]
        ]
        self._put_planned_units(target_relation_ids)

        # TODO: this is where sub-clusters configured to auto-generated should trigger recompute
        # we should make the one with "min(rel_id)" propose to change?

    def _rel_data(self) -> Union[PeerClusterRelData, PeerClusterRelErrorData]:
        """Build and return the peer cluster rel data to be shared with requirer sub-clusters."""
        if rel_err_data := self._rel_err_data():
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
        deployment_desc = self.peer_cm.deployment_desc()
        orchestrators = PeerClusterOrchestrators.from_dict(
            self.charm.peers_data.get_object(Scope.APP, "orchestrators")
        )

        should_sever_relation, blocked_msg = False, None
        message_suffix = f"in related '{deployment_desc.typ}' peer-cluster"

        if not deployment_desc:
            blocked_msg = "'main/failover'-orchestrators not configured yet."
        elif deployment_desc.typ == DeploymentType.OTHER:
            should_sever_relation = True
            blocked_msg = "Related to non 'main/failover'-orchestrator cluster."
        elif orchestrators.failover_app and orchestrators.failover_cm_app != self.charm.app.name:
            should_sever_relation = True
            blocked_msg = "Cannot have 2 'failover'-orchestrators. Relate to the existing failover."
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
                if not self._fetch_local_cm_nodes():
                    blocked_msg = f"No reported 'cluster_manager' eligible nodes {message_suffix}"
            except OpenSearchHttpError as e:
                logger.error(e)
                blocked_msg = f"Could not fetch nodes {message_suffix}"

        if not blocked_msg:
            return None

        return PeerClusterRelErrorData(
            cluster_name=deployment_desc.config.cluster_name if deployment_desc else None,
            should_sever_relation=should_sever_relation,
            should_wait=not should_sever_relation,
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
        """Event received when a new main-failover cluster unit joins the fleet."""
        # self.charm.trigger_leader_peer_rel_changed()
        pass

    def _on_peer_cluster_relation_changed(self, event: RelationChangedEvent):
        """Peer cluster relation change hook. Crucial to capture changes from the provider side."""
        if not self.charm.unit.is_leader():
            return

        logger.debug("\n\n\n\n\n\n -------------------------------------------\n\t--- REQUIRER")

        # check if current cluster ready
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            event.defer()
            return

        if not (data := event.relation.data.get(event.app)):
            return

        # fetch main and failover clusters relations ids if any
        orchestrators = self._related_orchestrators(event, data)

        # fetch provider data and only set if one not already set (by another main/failover rel)
        if error_from_providers := self._error_from_providers(data, orchestrators):
            self._set_error(label="error_from_providers", error=error_from_providers)
            # todo: set errors in the deployment desc -- run_with relation data?
            return

        # we fetch the success data
        data = PeerClusterRelData.from_str(data["data"])

        # handle error states that can only be figured out from the requirer side
        if error_from_requirer := self._error_from_requirer(data, event.relation.id):
            self._set_error(label="error_from_requirer", error=error_from_requirer.to_dict())
            return

        # we clear previous error statuses
        self._clear_errors("error_from_provider", "error_from_requirer")

        # this means it's a previous "main orchestrator" that was unrelated then re-related
        if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            logger.debug("REQUIRER: DEMOTING")
            self.charm.opensearch_peer_cm.demote_to_failover_orchestrator()
            deployment_desc = self.charm.opensearch_peer_cm.deployment_desc()

        # broadcast that this cluster is a failover candidate, and let the main CM elect it or not
        if deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR:
            self.put_in_rel_data(
                data={"candidate_failover_orchestrator_app": self.charm.app.name}, rel_id=event.relation.id
            )

        # register main and failover cm app names if any
        self.charm.peers_data.put_object(Scope.APP, "orchestrators", orchestrators.to_dict())

        # store the security related settings in secrets, peer_data, disk
        self._set_security_conf(data)

        # check if there are any security misconfigurations / violations
        if error_from_tls := self._error_from_tls(data):
            self._set_error(label="error_from_tls", error=error_from_tls)
            if error_from_tls.should_wait:
                event.defer()
            return

        self._clear_errors("error_from_tls")

        # aggregate all CMs (main + failover if any)
        for cm_node in self._cm_nodes(orchestrators):
            if cm_node not in data.cm_nodes:
                data.cm_nodes.append(cm_node)

        # recompute the deployment desc
        self.charm.opensearch_peer_cm.run_with_relation_data(data)
        logger.debug("\n------------------------------------------------\n\n\n")

    def _set_security_conf(self, data: PeerClusterRelData) -> None:
        """Store security related config."""
        # set admin secrets
        self.charm.secrets.put(Scope.APP, ADMIN_PW, data.credentials.admin_password)
        self.charm.secrets.put(Scope.APP, ADMIN_PW_HASH, data.credentials.admin_password_hash)
        self.charm.secrets.put_object(Scope.APP, CertType.APP_ADMIN.val, data.credentials.admin_tls)

        # store the app admin TLS resources if not stored
        self.charm.store_tls_resources(CertType.APP_ADMIN, data.credentials.admin_tls)

        # set user and security_index initialized flags
        self.charm.peers_data.put(Scope.APP, "admin_user_initialized", True)
        self.charm.peers_data.put(Scope.APP, "security_index_initialised", True)

        logger.debug("REQUIRER: _on_peer_cluster_relation_changed: STORED EVERYTHING NEEDED...")

    def _related_orchestrators(
        self, event: RelationChangedEvent, data: MutableMapping[str, str]
    ) -> PeerClusterOrchestrators:
        """Fetch related orchestrator IDs and App names."""
        # fetch the (main/failover)-cluster-orchestrator relations
        cm_relations = dict([(rel.id, rel.app.name) for rel in self.model.relations[self.relation_name]])

        orchestrators = self.get_obj_from_rel_data(
            key="orchestrators", rel_id=event.relation.id, rel_app=True
        )
        for rel_id, rel_app_name in cm_relations.items():
            logger.debug(f"RELATION: {rel_id}:{rel_app_name}")
            orchestrators.update(
                self.get_obj_from_rel_data(
                    key="orchestrators", rel_id=rel_id, rel_app=True
                )
            )
            logger.debug(f"\nRELATION: {rel_id}:{rel_app_name}\n\t{orchestrators}")

        if not orchestrators:
            orchestrators = json.loads(data["orchestrators"])
            logger.debug(f"\nRELATION: peer_orchestrators: {orchestrators}")

        return PeerClusterOrchestrators.from_dict(orchestrators)

    def _on_peer_cluster_relation_departed(self, event: RelationDepartedEvent):
        """Handle when 'main/failover'-CMs leave the relation (app or relation removal)."""
        if not self.charm.unit.is_leader():
            return

        logger.debug(f"\n\n\n_on_peer_cluster_relation_departed: {event.relation.id}")

        # fetch registered orchestrators
        orchestrators = PeerClusterOrchestrators.from_dict(
            self.charm.peers_data.get_object(Scope.APP, "orchestrators")
        )
        logger.debug(f"\n\n\n_on_peer_cluster_relation_departed: \n{orchestrators}\n\n")

        # a cluster of type "other" is departing (wrong relation), we can safely ignore.
        if event.relation.id not in [orchestrators.main_rel_id, orchestrators.failover_rel_id]:
            return

        # check the cluster which triggered this hook
        event_src_cluster_type = (
            "main" if event.relation.id == orchestrators.main_rel_id else "failover"
        )

        if self.charm.opensearch_peer_cm.deployment_desc().typ == DeploymentType.OTHER:
            orchestrators.delete(event_src_cluster_type)
            self.charm.peers_data.put(Scope.APP, "orchestrators", orchestrators.to_dict())
            return

        # from here on, the current app is either a "main" or potential "failover" clusters

        # handle scale-down at the charm level storage detaching, or??
        if relation_departure_reason(self.charm, self.relation_name) == RelDepartureReason.SCALE_DOWN:
            return

        # fetch cluster manager nodes across all peer clusters
        cms = self._cm_nodes(orchestrators)

        # delete the orchestrator that triggered this event
        orchestrators.delete(event_src_cluster_type)

        # the 'main' cluster orchestrator is the one being removed
        if event_src_cluster_type == "main":
            self._handle_main_orchestrator_departure(orchestrators, cms)

        self.charm.peers_data.put(Scope.APP, "orchestrators", orchestrators.to_dict())

        # let's broadcast the new conf to all related apps
        for rel_id in [rel.id for rel in self.charm.model.relations[self.relation_name]]:
            self.put_in_rel_data(data={"orchestrators": orchestrators.to_dict()}, rel_id=rel_id)

    def _handle_main_orchestrator_departure(
        self, orchestrators: PeerClusterOrchestrators, cms: List[Node]
    ) -> None:
        """Handle the departure of the main orchestrator."""
        if not orchestrators.failover_app:
            self.charm.status.set(
                BlockedStatus("Main-cluster-orchestrator removed, and no failover cluster related.")
            )
            self.charm.peers_data.put(Scope.APP, "orchestrators", orchestrators.to_dict())
            return

        if orchestrators.failover_app != self.charm.app.name:
            self.charm.peers_data.put(Scope.APP, "orchestrators", orchestrators.to_dict())
            return

        # current cluster is failover
        self.charm.opensearch_peer_cm.promote_to_main_orchestrator()

        # ensuring quorum
        main_cms = [cm for cm in cms if cm.app_name == orchestrators.main_app]
        non_main_cms = [cm for cm in cms if cm not in main_cms]
        if len(non_main_cms) % 2 == 0:
            message = "Scale-up this application by an odd number of units{} to ensure quorum."
            if (
                relation_departure_reason(self.charm, self.relation_name) == RelDepartureReason.REL_BROKEN
                and len(main_cms) % 2 == 1
            ):
                message = message.format(f"and scale-'down/up' {orchestrators.main_app} by 1 unit.")

            self.charm.status.set(message)

        # update peer rel data of current unit
        orchestrators.promote_failover()

    def _cm_nodes(self, orchestrators: PeerClusterOrchestrators) -> List[Node]:
        """Fetch the cm nodes passed from the peer cluster relation not api call."""
        cm_nodes = []
        for rel_id in [orchestrators.main_rel_id, orchestrators.failover_rel_id]:
            if rel_id == -1:
                continue

            cms = self.get_obj_from_rel_data(key="data", rel_id=rel_id, rel_app=True)
            cm_nodes.extend(cms)

        # attempt to have complete / real list of CMs
        try:
            for attempt in Retrying(stop=stop_after_attempt(3), wait=wait_fixed(0.5)):
                with attempt:
                    all_nodes = ClusterTopology.nodes(
                        self.charm.opensearch,
                        self.charm.opensearch.is_node_up(),
                        hosts=self.charm.alt_hosts + [node.ip for node in cm_nodes]
                    )
                    cm_nodes.extend([node for node in all_nodes if node.is_cm_eligible()])
        except RetryError:
            pass

        return cm_nodes

    def _error_from_providers(
        self, data: Optional[MutableMapping[str, Any]], orchestrators: PeerClusterOrchestrators
    ) -> Optional[Dict[str, Any]]:
        """Return the error data broadcast through the relation."""
        # check for errors in alternate relation (in case related to main and failover)
        # so we don't keep overriding the statuses
        error_data = None
        if orchestrators.main_rel_id != -1:
            error_data = self.get_obj_from_rel_data(
                key="error_data", rel_id=orchestrators.main_rel_id, rel_app=True
            )
        elif "error_data" in (data or {}):
            error_data = json.loads(data["error_data"])
        elif orchestrators.failover_rel_id != -1:
            error_data = self.get_obj_from_rel_data(
                key="error_data", rel_id=orchestrators.main_rel_id, rel_app=True
            )

        return error_data

    def _error_from_requirer(
        self, peer_cluster_rel_data: PeerClusterRelData, event_rel_id: int
    ) -> Optional[PeerClusterRelErrorData]:
        """Fetch error when relation is wrong and can only be computed on the requirer side."""
        orchestrators = PeerClusterOrchestrators.from_dict(
            self.charm.peers_data.get_object(Scope.APP, "orchestrators")
        )
        if not orchestrators.main_app and not orchestrators.failover_app:
            return None

        blocked_msg = None
        if (deployment_desc := self.peer_cm.deployment_desc()).typ == DeploymentType.MAIN_ORCHESTRATOR:
            blocked_msg = "Main cluster-orchestrator cannot be requirer of relation."
        elif event_rel_id not in [orchestrators.main_rel_id, orchestrators.failover_rel_id]:
            blocked_msg = ("A cluster can only be related to 1 main and 1 "
                           "failover-clusters at most.")

        if not blocked_msg:
            return None

        return PeerClusterRelErrorData(
            cluster_name=peer_cluster_rel_data.cluster_name,
            should_sever_relation=True,
            should_wait=False,
            blocked_message=blocked_msg,
            deployment_desc=deployment_desc,
        )

    def _error_from_tls(self, peer_cluster_rel_data: PeerClusterRelData) -> Optional[PeerClusterRelErrorData]:
        """Compute TLS related errors."""
        blocked_msg, should_sever_relation, should_wait = None, False, True

        if not self.charm.is_tls_fully_configured():  # check if TLS ready
            blocked_msg = (
                TLSNotFullyConfigured
                if self.charm.model.get_relation(TLS_RELATION)
                else TLSRelationMissing
            )
        else:  # compare CAs
            unit_transport_ca_cert = self.charm.secrets.get_object(
                Scope.UNIT, CertType.UNIT_TRANSPORT.val
            )["ca-cert"]
            if unit_transport_ca_cert != peer_cluster_rel_data.credentials.admin_tls["ca-cert"]:
                blocked_msg = "CA certificate mismatch between clusters."
                should_sever_relation, should_wait = True, False

        if not blocked_msg:
            return None

        return PeerClusterRelErrorData(
            cluster_name=peer_cluster_rel_data.cluster_name,
            should_sever_relation=should_sever_relation,
            should_wait=should_wait,
            blocked_message=blocked_msg,
            deployment_desc=self.peer_cm.deployment_desc(),
        )

    def _set_error(self, label: str, error: Optional[Dict[str, Any]]) -> None:
        """Set error status from the passed errors and store for future deletion."""
        error = PeerClusterRelErrorData.from_dict(error)
        err_message = error.blocked_message
        self.charm.status.set(
            WaitingStatus(err_message) if error.should_wait else BlockedStatus(err_message),
            app=True,
        )

        # we should keep track of set messages for targeted deletion later
        self.charm.peers_data.put(Scope.APP, label, err_message)

    def _clear_errors(self, *error_labels: str):
        """Clear previously set Peer clusters related statuses."""
        for error_label in error_labels:
            self.charm.status.clear(error_label)
            self.charm.peers_data.delete(error_label)
