# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Peer clusters relation related classes for OpenSearch."""
import json
import logging
from typing import TYPE_CHECKING, Any, Dict, List, MutableMapping, Optional, Union

from charms.opensearch.v0.constants_charm import (
    PeerClusterOrchestratorRelationName,
    PeerClusterRelationName,
)
from charms.opensearch.v0.constants_secrets import ADMIN_PW, ADMIN_PW_HASH
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_charm import (
    RelDepartureReason,
    relation_departure_reason,
)
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.models import (
    DeploymentDescription,
    DeploymentType,
    Node,
    PeerClusterOrchestrators,
    PeerClusterRelData,
    PeerClusterRelDataCredentials,
    PeerClusterRelErrorData,
    S3RelDataCredentials,
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
from tenacity import RetryError, Retrying, stop_after_attempt, wait_fixed

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

    def get_from_rel(
        self, key: str, rel_id: int = None, remote_app: bool = False
    ) -> Optional[str]:
        """Fetch relation data by key from relation id (from an int or relation event)."""
        if not rel_id:
            raise ValueError("Relation id must be provided as arguments.")

        relation = self.get_rel(rel_id=rel_id)
        if relation:
            return relation.data[relation.app if remote_app else self.charm.app].get(key)

        return None

    def get_obj_from_rel(
        self, key: str, rel_id: int = None, remote_app: bool = True
    ) -> Dict[Any, Any]:
        """Get object from peer cluster relation data."""
        data = self.get_from_rel(key, rel_id=rel_id, remote_app=remote_app) or "{}"
        return json.loads(data)

    def put_in_rel(self, data: Dict[str, Any], rel_id: Optional[int] = None) -> None:
        """Put object in peer cluster rel data."""
        if not rel_id:
            raise ValueError("Relation id must be provided as arguments.")

        relation = self.get_rel(rel_id=rel_id)
        if relation:
            relation.data[self.charm.app].update(data)

    def delete_from_rel(
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
            charm.on[self.relation_name].relation_departed,
            self._on_peer_cluster_relation_departed,
        )

    def _on_peer_cluster_relation_joined(self, event: RelationJoinedEvent):
        """Received by all units in main/failover clusters when new sub-cluster joins the rel."""
        if not self.charm.unit.is_leader():
            return

        self.refresh_relation_data(event)

        # TODO: is the below still needed
        # self.charm.trigger_leader_peer_rel_changed()

    def _on_peer_cluster_relation_changed(self, event: RelationChangedEvent):
        """Event received by all units in sub-cluster when a new sub-cluster joins the relation."""
        if not self.charm.unit.is_leader():
            return

        # the current app is not ready
        if not (deployment_desc := self.peer_cm.deployment_desc()):
            event.defer()
            return

        # only the main-orchestrator is able to designate a failover
        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            return

        if not (data := event.relation.data.get(event.app)):
            return

        # get list of relations with this orchestrator
        target_relation_ids = [rel.id for rel in self.charm.model.relations[self.relation_name]]

        # fetch emitting app planned units and broadcast
        self._put_planned_units(
            event.app.name, json.loads(data.get("planned_units")), target_relation_ids
        )

        if not (candidate_failover_app := data.get("candidate_failover_orchestrator_app")):
            self.refresh_relation_data(event)
            return

        orchestrators = PeerClusterOrchestrators.from_dict(
            self.charm.peers_data.get_object(Scope.APP, "orchestrators")
        )
        if orchestrators.failover_app and orchestrators.failover_rel_id in target_relation_ids:
            logger.info("A failover cluster orchestrator is already registered.")
            self.refresh_relation_data(event)
            return

        # register the new failover in the current main peer relation data
        orchestrators.failover_app = candidate_failover_app
        orchestrators.failover_rel_id = event.relation.id
        self.charm.peers_data.put_object(Scope.APP, "orchestrators", orchestrators.to_dict())

        # broadcast the new failover in all the cluster fleet
        for rel_id in target_relation_ids:
            orchestrators = PeerClusterOrchestrators.from_dict(
                self.get_obj_from_rel("orchestrators", rel_id, remote_app=False)
            )
            orchestrators.failover_app = candidate_failover_app
            self.put_in_rel(
                data={"orchestrators": json.dumps(orchestrators.to_dict())}, rel_id=rel_id
            )

    def _on_peer_cluster_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Event received by all units in sub-cluster when a sub-cluster leaves the relation."""
        if not self.charm.unit.is_leader():
            return

        # we need to update the fleet planned units
        target_relation_ids = [rel.id for rel in self.charm.model.relations[self.relation_name]]
        self._put_planned_units(event.app.name, 0, target_relation_ids)

    def refresh_relation_data(self, event: EventBase) -> None:
        """Refresh the peer cluster rel data (new cm node, admin password change etc.)."""
        if not self.charm.unit.is_leader():
            return

        # all relations with the current orchestrator
        all_relation_ids = [rel.id for rel in self.charm.model.relations[self.relation_name]]

        # get deployment descriptor of current app
        deployment_desc = self.charm.opensearch_peer_cm.deployment_desc()

        # fetch stored orchestrators
        orchestrators = PeerClusterOrchestrators.from_dict(
            self.charm.peers_data.get_object(Scope.APP, "orchestrators")
        )

        # compute the data that needs to be broadcast to all related clusters (success or error)
        rel_data = self._rel_data(deployment_desc, orchestrators)

        # exit if current cluster should not have been considered a provider
        if self._notify_if_wrong_integration(rel_data, all_relation_ids):
            return

        # store the main/failover-cm planned units count
        self._put_planned_units(
            self.charm.app.name, self.charm.app.planned_units(), all_relation_ids
        )

        cluster_type = (
            "main" if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR else "failover"
        )

        # update reported orchestrators on local orchestrator
        orchestrators = orchestrators.to_dict()
        orchestrators[f"{cluster_type}_app"] = self.charm.app.name
        self.charm.peers_data.put_object(Scope.APP, "orchestrators", orchestrators)

        peer_rel_data_key, should_defer = "data", False
        if isinstance(rel_data, PeerClusterRelErrorData):
            peer_rel_data_key, should_defer = "error_data", rel_data.should_wait

        # save the orchestrators of this fleet
        for rel_id in all_relation_ids:
            orchestrators = self.get_obj_from_rel("orchestrators", rel_id=rel_id)
            orchestrators.update(
                {
                    f"{cluster_type}_app": self.charm.app.name,
                    f"{cluster_type}_rel_id": rel_id,
                }
            )
            self.put_in_rel(data={"orchestrators": json.dumps(orchestrators)}, rel_id=rel_id)

            # there is no error to broadcast - we clear any previously broadcasted error
            if isinstance(rel_data, PeerClusterRelData):
                self.delete_from_rel("error_data", rel_id=rel_id)

            # are we potentially overriding stuff here?
            self.put_in_rel(
                data={peer_rel_data_key: json.dumps(rel_data.to_dict())}, rel_id=rel_id
            )

        if should_defer:
            event.defer()

    def _notify_if_wrong_integration(
        self,
        rel_data: Union[PeerClusterRelData, PeerClusterRelErrorData],
        target_relation_ids: List[int],
    ) -> bool:
        """Check if relation is invalid and notify related sub-clusters."""
        if not isinstance(rel_data, PeerClusterRelErrorData):
            return False

        if not rel_data.should_sever_relation:
            return False

        for rel_id in target_relation_ids:
            self.put_in_rel(data={"error_data": json.dumps(rel_data.to_dict())}, rel_id=rel_id)

        return True

    def _put_planned_units(self, app: str, count: int, target_relation_ids: List[int]):
        """Save in the peer cluster rel data the planned units count per app."""
        cluster_fleet_planned_units = (
            self.charm.peers_data.get_object(Scope.APP, "cluster_fleet_planned_units") or {}
        )

        # TODO: need to ensure unicity of app name for cross models
        cluster_fleet_planned_units.update({app: count})
        cluster_fleet_planned_units.update({self.charm.app.name: self.charm.app.planned_units()})

        for rel_id in target_relation_ids:
            self.put_in_rel(
                data={"cluster_fleet_planned_units": json.dumps(cluster_fleet_planned_units)},
                rel_id=rel_id,
            )

        self.charm.peers_data.put_object(
            Scope.APP, "cluster_fleet_planned_units", cluster_fleet_planned_units
        )

    def _rel_data(
        self, deployment_desc: DeploymentDescription, orchestrators: PeerClusterOrchestrators
    ) -> Union[PeerClusterRelData, PeerClusterRelErrorData]:
        """Build and return the peer cluster rel data to be shared with requirer sub-clusters."""
        if rel_err_data := self._rel_err_data(deployment_desc, orchestrators):
            return rel_err_data

        # check that this cluster is fully ready, otherwise put "configuring" in
        # peer rel data for requirers to show a blocked status until it's fully
        # ready (will receive a subsequent
        try:
            secrets = self.charm.secrets

            if self.deployent_desc().typ == DeploymentType.MAIN_ORCHESTRATOR:
                # As the main orchestrator, this application must set the S3 information.
                s3_credentials = S3RelDataCredentials(
                    access_key=self.charm.s3_client.get_s3_connection_info().get("access-key", ""),
                    secret_key=self.charm.s3_client.get_s3_connection_info().get("secret-key", ""),
                )
            else:
                # Return what we have received from the peer relation
                s3_credentials = S3RelDataCredentials(
                    access_key=secrets.get(Scope.APP, "access-key", default=None),
                    secret_key=secrets.get(Scope.APP, "secret-key", default=None),
                )
            return PeerClusterRelData(
                cluster_name=deployment_desc.config.cluster_name,
                cm_nodes=self._fetch_local_cm_nodes(),
                credentials=PeerClusterRelDataCredentials(
                    admin_username="admin",
                    admin_password=secrets.get(Scope.APP, ADMIN_PW),
                    admin_password_hash=secrets.get(Scope.APP, ADMIN_PW_HASH),
                    admin_tls=secrets.get_object(Scope.APP, CertType.APP_ADMIN.val),
                ),
                s3_credentials=s3_credentials,
                deployment_desc=deployment_desc,
            )
        except OpenSearchHttpError:
            return PeerClusterRelErrorData(
                cluster_name=deployment_desc.config.cluster_name,
                should_sever_relation=False,
                should_wait=True,
                blocked_message=f"Could not fetch nodes in related {deployment_desc.typ} sub-cluster.",
                deployment_desc=deployment_desc,
            )

    def _rel_err_data(  # noqa: C901
        self, deployment_desc: DeploymentDescription, orchestrators: PeerClusterOrchestrators
    ) -> Optional[PeerClusterRelErrorData]:
        """Build error peer relation data object."""
        should_sever_relation, blocked_msg = False, None
        message_suffix = f"in related '{deployment_desc.typ}'"

        if not deployment_desc:
            blocked_msg = "'main/failover'-orchestrators not configured yet."
        elif deployment_desc.typ == DeploymentType.OTHER:
            should_sever_relation = True
            blocked_msg = "Related to non 'main/failover'-orchestrator cluster."
        elif orchestrators.failover_app and orchestrators.failover_app != self.charm.app.name:
            should_sever_relation = True
            blocked_msg = (
                "Cannot have 2 'failover'-orchestrators. Relate to the existing failover."
            )
        elif not self.charm.is_admin_user_configured():
            blocked_msg = f"Admin user not fully configured {message_suffix}."
        elif not self.charm.is_tls_full_configured_in_cluster():
            blocked_msg = f"TLS not fully configured {message_suffix}."
        elif not self.charm.peers_data.get(Scope.APP, "security_index_initialised", False):
            blocked_msg = f"Security index not initialized {message_suffix}."
        elif not self.charm.is_every_unit_marked_as_started():
            blocked_msg = f"Waiting for every unit {message_suffix} to start."
        else:
            try:
                if not self._fetch_local_cm_nodes():
                    blocked_msg = f"No 'cluster_manager' eligible nodes found {message_suffix}"
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
            charm.on[self.relation_name].relation_departed,
            self._on_peer_cluster_relation_departed,
        )

    def _on_peer_cluster_relation_joined(self, event: RelationJoinedEvent):
        """Event received when a new main-failover cluster unit joins the fleet."""
        # self.charm.trigger_leader_peer_rel_changed()
        pass

    def _on_peer_cluster_relation_changed(self, event: RelationChangedEvent):
        """Peer cluster relation change hook. Crucial to capture changes from the provider side."""
        if not self.charm.unit.is_leader():
            return

        # register in the 'main/failover'-CMs / save the number of planned units of the current app
        self._put_planned_units(event)

        # check if current cluster ready
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            event.defer()
            return

        if not (data := event.relation.data.get(event.app)):
            return

        # fetch main and failover clusters relations ids if any
        orchestrators = self._orchestrators(event, data, deployment_desc)

        # check errors sent by providers
        if self._error_set_from_providers(orchestrators, data, event.relation.id):
            return

        # fetch the success data
        data = PeerClusterRelData.from_str(data["data"])

        # check errors that can only be figured out from the requirer side
        if self._error_set_from_requirer(orchestrators, deployment_desc, data, event.relation.id):
            return

        # this means it's a previous "main orchestrator" that was unrelated then re-related
        if deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            self.charm.opensearch_peer_cm.demote_to_failover_orchestrator()
            deployment_desc = self.charm.opensearch_peer_cm.deployment_desc()

        # broadcast that this cluster is a failover candidate, and let the main CM elect it or not
        if deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR:
            self.put_in_rel(
                data={"candidate_failover_orchestrator_app": self.charm.app.name},
                rel_id=event.relation.id,
            )

        # register main and failover cm app names if any
        self.charm.peers_data.put_object(Scope.APP, "orchestrators", orchestrators.to_dict())

        # store the security related settings in secrets, peer_data, disk
        self._set_security_conf(data)

        # check if there are any security misconfigurations / violations
        if self._error_set_from_tls(data):
            event.defer()
            return

        # aggregate all CMs (main + failover if any)
        data.cm_nodes = self._cm_nodes(orchestrators)

        # recompute the deployment desc
        self.charm.opensearch_peer_cm.run_with_relation_data(data)

    def _set_security_conf(self, data: PeerClusterRelData) -> None:
        """Store security related config."""
        # set admin secrets
        self.charm.secrets.put(Scope.APP, ADMIN_PW, data.credentials.admin_password)
        self.charm.secrets.put(Scope.APP, ADMIN_PW_HASH, data.credentials.admin_password_hash)
        self.charm.secrets.put_object(
            Scope.APP, CertType.APP_ADMIN.val, data.credentials.admin_tls
        )

        # store the app admin TLS resources if not stored
        self.charm.store_tls_resources(CertType.APP_ADMIN, data.credentials.admin_tls)

        # set user and security_index initialized flags
        self.charm.peers_data.put(Scope.APP, "admin_user_initialized", True)
        self.charm.peers_data.put(Scope.APP, "security_index_initialised", True)

        self.charm.secrets.put(Scope.APP, "access-key", data.s3_credentials.access_key)
        self.charm.secrets.put(Scope.APP, "secret-key", data.s3_credentials.secret_key)

    def _orchestrators(
        self,
        event: RelationChangedEvent,
        data: MutableMapping[str, str],
        deployment_desc: DeploymentDescription,
    ) -> PeerClusterOrchestrators:
        """Fetch related orchestrator IDs and App names."""
        orchestrators = self.get_obj_from_rel(key="orchestrators", rel_id=event.relation.id)

        # fetch the (main/failover)-cluster-orchestrator relations
        cm_relations = dict(
            [(rel.id, rel.app.name) for rel in self.model.relations[self.relation_name]]
        )
        for rel_id, rel_app_name in cm_relations.items():
            orchestrators.update(self.get_obj_from_rel(key="orchestrators", rel_id=rel_id))

        if not orchestrators:
            orchestrators = json.loads(data["orchestrators"])

        # handle case where the current is a designated failover
        if deployment_desc.typ == DeploymentType.FAILOVER_ORCHESTRATOR:
            local_orchestrators = PeerClusterOrchestrators.from_dict(
                self.charm.peers_data.get_object(Scope.APP, "orchestrators") or {}
            )
            if local_orchestrators.failover_app == self.charm.app.name:
                orchestrators["failover_app"] = local_orchestrators.failover_app

        return PeerClusterOrchestrators.from_dict(orchestrators)

    def _put_planned_units(self, event: RelationEvent):
        """Report self planned units and store the fleet's on the peer data bag."""
        # register the number of planned units in the current app, to notify the orchestrators
        self.put_in_rel(
            data={"planned_units": json.dumps(self.charm.app.planned_units())},
            rel_id=event.relation.id,
        )

        # self in the current app's peer databag
        cluster_fleet_planned_units = self.get_obj_from_rel(
            "cluster_fleet_planned_units", rel_id=event.relation.id
        )
        cluster_fleet_planned_units.update({self.charm.app.name: self.charm.app.planned_units()})

        self.charm.peers_data.put_object(
            Scope.APP, "cluster_fleet_planned_units", cluster_fleet_planned_units
        )

    def _on_peer_cluster_relation_departed(self, event: RelationDepartedEvent):
        """Handle when 'main/failover'-CMs leave the relation (app or relation removal)."""
        if not self.charm.unit.is_leader():
            return

        # fetch registered orchestrators
        orchestrators = PeerClusterOrchestrators.from_dict(
            self.charm.peers_data.get_object(Scope.APP, "orchestrators")
        )

        # a cluster of type "other" is departing (wrong relation), or, the current is a main
        # orchestrator and a failover is departing, we can safely ignore.
        if event.relation.id not in [orchestrators.main_rel_id, orchestrators.failover_rel_id]:
            self._clear_errors(f"error_from_requirer-{event.relation.id}")
            return

        # handle scale-down at the charm level storage detaching, or??
        if (
            relation_departure_reason(self.charm, self.relation_name)
            == RelDepartureReason.SCALE_DOWN
        ):
            return

        # fetch cluster manager nodes from API + across all peer clusters
        cms = self._cm_nodes(orchestrators)

        # check the departed cluster which triggered this hook
        event_src_cluster_type = (
            "main" if event.relation.id == orchestrators.main_rel_id else "failover"
        )

        # delete the orchestrator that triggered this event
        orchestrators.delete(event_src_cluster_type)

        # the 'main' cluster orchestrator is the one being removed
        failover_promoted = False
        if event_src_cluster_type == "main":
            if not orchestrators.failover_app:
                self.charm.status.set(
                    BlockedStatus(
                        "Main-cluster-orchestrator removed, and no failover cluster related."
                    )
                )
            elif orchestrators.failover_app == self.charm.app.name:
                self._promote_failover(orchestrators, cms)
                failover_promoted = True

        self.charm.peers_data.put_object(Scope.APP, "orchestrators", orchestrators.to_dict())

        # clear previously set errors due to this relation
        self._clear_errors(f"error_from_provider-{event.relation.id}")
        self._clear_errors(f"error_from_requirer-{event.relation.id}")

        # we leave in case not an orchestrator
        if (
            self.charm.opensearch_peer_cm.deployment_desc().typ == DeploymentType.OTHER
            or self.charm.app.name not in [orchestrators.main_app, orchestrators.failover_app]
        ):
            return

        # the current is an orchestrator, let's broadcast the new conf to all related apps
        for rel_id in [
            rel.id for rel in self.charm.model.relations[PeerClusterOrchestratorRelationName]
        ]:
            rel_orchestrators = PeerClusterOrchestrators.from_dict(
                self.get_obj_from_rel("orchestrators", rel_id, remote_app=False)
            )

            rel_orchestrators.delete(event_src_cluster_type)
            if failover_promoted:
                rel_orchestrators.promote_failover()

            self.put_in_rel(
                data={"orchestrators": json.dumps(rel_orchestrators.to_dict())}, rel_id=rel_id
            )

    def _promote_failover(self, orchestrators: PeerClusterOrchestrators, cms: List[Node]) -> None:
        """Handle the departure of the main orchestrator."""
        # current cluster is failover
        self.charm.opensearch_peer_cm.promote_to_main_orchestrator()

        # ensuring quorum
        main_cms = [cm for cm in cms if cm.app_name == orchestrators.main_app]
        non_main_cms = [cm for cm in cms if cm not in main_cms]
        if len(non_main_cms) % 2 == 0:
            departure_reason = relation_departure_reason(self.charm, self.relation_name)
            message = "Scale-up this application by an odd number of units{} to ensure quorum."
            if len(main_cms) % 2 == 1 and departure_reason == RelDepartureReason.REL_BROKEN:
                message = message.format(
                    f" and scale-'down/up' {orchestrators.main_app} by 1 unit"
                )

            self.charm.status.set(message)

        # remove old main and promote new failover
        orchestrators.promote_failover()

    def _cm_nodes(self, orchestrators: PeerClusterOrchestrators) -> List[Node]:
        """Fetch the cm nodes passed from the peer cluster relation not api call."""
        cm_nodes = {}
        for rel_id in [orchestrators.main_rel_id, orchestrators.failover_rel_id]:
            if rel_id == -1:
                continue

            data = self.get_obj_from_rel(key="data", rel_id=rel_id)
            if not data:  # not ready yet
                continue

            data = PeerClusterRelData.from_dict(data)
            cm_nodes = {**cm_nodes, **{node.name: node for node in data.cm_nodes}}

        # attempt to have an opensearch reported list of CMs - the response
        # may be smaller or greater than previous list.
        try:
            for attempt in Retrying(stop=stop_after_attempt(3), wait=wait_fixed(0.5)):
                with attempt:
                    all_nodes = ClusterTopology.nodes(
                        self.charm.opensearch,
                        self.charm.opensearch.is_node_up(),
                        hosts=self.charm.alt_hosts + [node.ip for node in cm_nodes],
                    )
                    cm_nodes = {
                        **cm_nodes,
                        **{node.name: node for node in all_nodes if node.is_cm_eligible()},
                    }
        except RetryError:
            pass

        return list(cm_nodes.values())

    def _error_set_from_providers(
        self,
        orchestrators: PeerClusterOrchestrators,
        event_data: Optional[MutableMapping[str, Any]],
        event_rel_id: int,
    ) -> bool:
        """Check if the providers are ready and set error if not."""
        orchestrator_rel_ids = [
            rel_id
            for rel_id in [orchestrators.main_rel_id, orchestrators.failover_rel_id]
            if rel_id != -1
        ]

        error = None
        for rel_id in orchestrator_rel_ids:
            data = self.get_obj_from_rel("data", rel_id=rel_id)
            error_data = self.get_obj_from_rel("error_data", rel_id=rel_id)
            if not data and not error_data:  # relation data still incomplete
                return True

            if error_data:
                error = error_data
                break

        # we handle the case where the error came from the provider of a wrong relation
        if not error and "error_data" in (event_data or {}):
            error = json.loads(event_data["error_data"])

        if error:
            self._set_error(f"error_from_providers-{event_rel_id}", error)
            return True

        self._clear_errors(f"error_from_providers-{event_rel_id}")
        return False

    def _error_set_from_requirer(
        self,
        orchestrators: PeerClusterOrchestrators,
        deployment_desc: DeploymentDescription,
        peer_cluster_rel_data: PeerClusterRelData,
        event_rel_id: int,
    ) -> bool:
        """Fetch error when relation is wrong and can only be computed on the requirer side."""
        blocked_msg = None
        if (
            deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR
            and deployment_desc.promotion_time
            > peer_cluster_rel_data.deployment_desc.promotion_time
        ):
            blocked_msg = "Main cluster-orchestrator cannot be requirer of relation."
        elif event_rel_id not in [orchestrators.main_rel_id, orchestrators.failover_rel_id]:
            blocked_msg = (
                "A cluster can only be related to 1 main and 1 failover-clusters at most."
            )

        if not blocked_msg:
            self._clear_errors(f"error_from_requirer-{event_rel_id}")
            return False

        self._set_error(
            label=f"error_from_requirer-{event_rel_id}",
            error=PeerClusterRelErrorData(
                cluster_name=peer_cluster_rel_data.cluster_name,
                should_sever_relation=True,
                should_wait=False,
                blocked_message=blocked_msg,
                deployment_desc=deployment_desc,
            ).to_dict(),
        )
        return True

    def _error_set_from_tls(self, peer_cluster_rel_data: PeerClusterRelData) -> bool:
        """Compute TLS related errors."""
        blocked_msg, should_sever_relation = None, False

        if self.charm.is_tls_fully_configured():  # compare CAs
            unit_transport_ca_cert = self.charm.secrets.get_object(
                Scope.UNIT, CertType.UNIT_TRANSPORT.val
            )["ca-cert"]
            if unit_transport_ca_cert != peer_cluster_rel_data.credentials.admin_tls["ca-cert"]:
                blocked_msg = "CA certificate mismatch between clusters."
                should_sever_relation = True

        if not blocked_msg:
            self._clear_errors("error_from_tls")
            return False

        self._set_error(
            label="error_from_tls",
            error=PeerClusterRelErrorData(
                cluster_name=peer_cluster_rel_data.cluster_name,
                should_sever_relation=should_sever_relation,
                should_wait=not should_sever_relation,
                blocked_message=blocked_msg,
                deployment_desc=self.peer_cm.deployment_desc(),
            ).to_dict(),
        )
        return True

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
            self.charm.peers_data.delete(Scope.APP, error_label)
