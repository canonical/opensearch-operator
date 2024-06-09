# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Managing simple or large deployments and configuration related changes."""
import logging
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from charms.opensearch.v0.constants_charm import (
    CMRoleRemovalForbidden,
    CmVoRolesProvidedInvalid,
    DataRoleRemovalForbidden,
    PClusterNoRelation,
    PClusterWrongNodesCountForQuorum,
    PClusterWrongRelation,
    PClusterWrongRolesProvided,
    PeerClusterOrchestratorRelationName,
)
from charms.opensearch.v0.helper_charm import (
    all_units,
    format_unit_name,
    trigger_peer_rel_changed,
)
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    DeploymentType,
    Directive,
    Node,
    PeerClusterConfig,
    PeerClusterFleetApps,
    PeerClusterOrchestrators,
    PeerClusterRelData,
    PeerClusterRelErrorData,
    StartMode,
    State,
)
from charms.opensearch.v0.opensearch_exceptions import OpenSearchError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import BlockedStatus
from shortuuid import ShortUUID

# The unique Charmhub library identifier, never change it
LIBID = "35ccf1a7eac946ec8f962c21401598d6"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm


class OpenSearchProvidedRolesException(OpenSearchError):
    """Exception class for events when the user provided node roles will violate quorum."""


class OpenSearchPeerClustersManager:
    """This class covers the configuration changes depending on certain actions."""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        self._charm = charm
        self._opensearch = charm.opensearch

    def run(self) -> None:
        """Init, or updates / recomputes current peer cluster related config if applies."""
        user_config = self._user_config()
        if not (current_deployment_desc := self.deployment_desc()):
            # new cluster
            deployment_desc = self._new_cluster_setup(user_config)
            self._charm.peers_data.put_object(
                Scope.APP, "deployment-description", deployment_desc.to_dict()
            )
            self.apply_status_if_needed(deployment_desc)
            return

        # update cluster deployment desc
        deployment_desc = self._existing_cluster_setup(user_config, current_deployment_desc)
        if current_deployment_desc == deployment_desc:
            return

        if deployment_desc.state.value == State.ACTIVE:
            # we only update the deployment desc if all is well.
            # TODO: Should we add an entry on DeploymentDesc "errors" to reflect on status?
            self._charm.peers_data.put_object(
                Scope.APP, "deployment-description", deployment_desc.to_dict()
            )

        if deployment_desc.start == StartMode.WITH_GENERATED_ROLES:
            # trigger roles change on the leader, other units will have their peer-rel-changed
            # event triggered
            trigger_peer_rel_changed(self._charm, on_other_units=False, on_current_unit=True)

        self.apply_status_if_needed(deployment_desc)

        # TODO: once peer clusters relation implemented, we should apply all directives
        #  + removing them from queue. We currently only apply the status.

    def run_with_relation_data(
        self, data: PeerClusterRelData, error_data: Optional[PeerClusterRelErrorData] = None
    ) -> None:
        """Update current peer cluster related config based on peer_cluster rel_data."""
        current_deployment_desc = self.deployment_desc()

        config = current_deployment_desc.config
        deployment_state = current_deployment_desc.state
        pending_directives = current_deployment_desc.pending_directives

        if Directive.WAIT_FOR_PEER_CLUSTER_RELATION in pending_directives:
            pending_directives.remove(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)

        if Directive.VALIDATE_CLUSTER_NAME in pending_directives:
            if config.cluster_name != data.cluster_name:
                deployment_state = DeploymentState(
                    value=State.BLOCKED_WRONG_RELATED_CLUSTER, message=PClusterWrongRelation
                )
            elif deployment_state.value in [
                State.BLOCKED_WRONG_RELATED_CLUSTER,
                State.BLOCKED_WAITING_FOR_RELATION,
            ]:
                deployment_state = DeploymentState(value=State.ACTIVE)
                pending_directives.remove(Directive.VALIDATE_CLUSTER_NAME)
        elif Directive.INHERIT_CLUSTER_NAME in pending_directives:
            config.cluster_name = data.cluster_name
            pending_directives.remove(Directive.INHERIT_CLUSTER_NAME)

        pending_directives.append(Directive.SHOW_STATUS)
        new_deployment_desc = DeploymentDescription(
            app=current_deployment_desc.app,
            config=config,
            pending_directives=pending_directives,
            typ=current_deployment_desc.typ,
            state=deployment_state,
            start=current_deployment_desc.start,
        )
        self._charm.peers_data.put_object(
            Scope.APP, "deployment-description", new_deployment_desc.to_dict()
        )

        self.apply_status_if_needed(new_deployment_desc)

    def _user_config(self):
        """Build a user provided config object."""
        return PeerClusterConfig(
            cluster_name=self._charm.config.get("cluster_name"),
            init_hold=self._charm.config.get("init_hold", False),
            roles=[
                option.strip().lower()
                for option in self._charm.config.get("roles", "").split(",")
                if option
            ],
        )

    def _new_cluster_setup(self, config: PeerClusterConfig) -> DeploymentDescription:
        """Build deployment description of a new cluster."""
        directives = []
        deployment_state = DeploymentState(value=State.ACTIVE)
        if config.init_hold:
            # checks if peer cluster relation is set
            if not self.is_peer_cluster_orchestrator_relation_set():
                deployment_state = DeploymentState(
                    value=State.BLOCKED_WAITING_FOR_RELATION, message=PClusterNoRelation
                )

                directives.append(Directive.SHOW_STATUS)

            directives.append(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)
            directives.append(
                Directive.VALIDATE_CLUSTER_NAME
                if config.cluster_name
                else Directive.INHERIT_CLUSTER_NAME
            )

            start_mode = (
                StartMode.WITH_PROVIDED_ROLES if config.roles else StartMode.WITH_GENERATED_ROLES
            )
            return DeploymentDescription(
                app=App(model_uuid=self._charm.model.uuid, name=self._charm.app.name),
                config=config,
                start=start_mode,
                pending_directives=directives,
                typ=self._deployment_type(config, start_mode),
                state=deployment_state,
            )

        cluster_name = (
            config.cluster_name.strip()
            or f"{self._charm.app.name}-{ShortUUID().random(length=4)}".lower()
        )

        if not config.roles:
            start_mode = StartMode.WITH_GENERATED_ROLES
        else:
            start_mode = StartMode.WITH_PROVIDED_ROLES
            if "cluster_manager" not in config.roles:
                deployment_state = DeploymentState(
                    value=State.BLOCKED_CANNOT_START_WITH_ROLES,
                    message=PClusterWrongRolesProvided,
                )
                directives.append(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)
                directives.append(Directive.SHOW_STATUS)

        return DeploymentDescription(
            app=App(model_uuid=self._charm.model.uuid, name=self._charm.app.name),
            config=PeerClusterConfig(
                cluster_name=cluster_name,
                init_hold=config.init_hold,
                roles=config.roles,
                data_temperature=config.data_temperature,
            ),
            start=start_mode,
            pending_directives=directives,
            typ=self._deployment_type(config, start_mode),
            state=deployment_state,
        )

    def _existing_cluster_setup(
        self, config: PeerClusterConfig, prev_deployment: DeploymentDescription
    ) -> DeploymentDescription:
        """Build deployment description of an existing (started or not) cluster."""
        directives = prev_deployment.pending_directives
        deployment_state = prev_deployment.state
        try:
            self._pre_validate_roles_change(
                new_roles=config.roles, prev_roles=prev_deployment.config.roles
            )
            if prev_deployment.state.value == State.BLOCKED_CANNOT_APPLY_NEW_ROLES:
                deployment_state = DeploymentState(value=State.ACTIVE, message="")
                directives.append(Directive.SHOW_STATUS)
            # todo: should we further handle states here?
        except OpenSearchProvidedRolesException as e:
            logger.error(e)
            directives.append(Directive.SHOW_STATUS)
            deployment_state = DeploymentState(
                value=State.BLOCKED_CANNOT_APPLY_NEW_ROLES, message=str(e)
            )

        start_mode = (
            StartMode.WITH_PROVIDED_ROLES if config.roles else StartMode.WITH_GENERATED_ROLES
        )
        if (
            not config.init_hold
            and prev_deployment.state.value == State.BLOCKED_CANNOT_START_WITH_ROLES
            and (start_mode == StartMode.WITH_GENERATED_ROLES or "cluster_manager" in config.roles)
        ):
            deployment_state = DeploymentState(value=State.ACTIVE, message="")
            directives.append(Directive.SHOW_STATUS)
            directives.remove(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)

        deployment_type = self._deployment_type(config, start_mode)
        return DeploymentDescription(
            app=prev_deployment.app,
            config=PeerClusterConfig(
                cluster_name=prev_deployment.config.cluster_name,
                init_hold=prev_deployment.config.init_hold,
                roles=config.roles,
                data_temperature=config.data_temperature,
            ),
            start=start_mode,
            state=deployment_state,
            typ=deployment_type,
            pending_directives=list(set(directives)),
            promotion_time=(
                prev_deployment.promotion_time
                if deployment_type == DeploymentType.MAIN_ORCHESTRATOR
                else None
            ),
        )

    def can_start(self, deployment_desc: Optional[DeploymentDescription] = None) -> bool:
        """Return whether the service of a node can start."""
        if not (deployment_desc := deployment_desc or self.deployment_desc()):
            return False

        blocking_directives = [
            Directive.WAIT_FOR_PEER_CLUSTER_RELATION,
            Directive.RECONFIGURE,
            Directive.VALIDATE_CLUSTER_NAME,
            Directive.INHERIT_CLUSTER_NAME,
        ]
        for directive in deployment_desc.pending_directives:
            if directive in blocking_directives:
                return False

        return True

    def apply_status_if_needed(
        self,
        deployment_desc: Optional[DeploymentDescription] = None,
        show_status_only_once: bool = True,
    ) -> None:
        """Resolve and applies corresponding status from the deployment state."""
        if not (deployment_desc := deployment_desc or self.deployment_desc()):
            return

        if Directive.SHOW_STATUS not in deployment_desc.pending_directives:
            return

        # remove show_status directive which is applied below
        if show_status_only_once:
            self.clear_directive(Directive.SHOW_STATUS)

        blocked_status_messages = [
            CMRoleRemovalForbidden,
            CmVoRolesProvidedInvalid,
            DataRoleRemovalForbidden,
            PClusterNoRelation,
            PClusterWrongNodesCountForQuorum,
            PClusterWrongRelation,
            PClusterWrongRolesProvided,
        ]
        if deployment_desc.state.message not in blocked_status_messages:
            for message in blocked_status_messages:
                self._charm.status.clear(message, app=True)
            return

        self._charm.app.status = BlockedStatus(deployment_desc.state.message)

    def clear_directive(self, directive: Directive):
        """Remove directive after having applied it."""
        if not (deployment_desc := self.deployment_desc()):
            return

        if directive not in deployment_desc.pending_directives:
            return

        deployment_desc.pending_directives.remove(directive)
        self._charm.peers_data.put_object(
            Scope.APP, "deployment-description", deployment_desc.to_dict()
        )

    def deployment_desc(self) -> Optional[DeploymentDescription]:
        """Return the deployment description object if any."""
        current_deployment_desc = self._charm.peers_data.get_object(
            Scope.APP, "deployment-description"
        )
        if not current_deployment_desc:
            return None

        return DeploymentDescription.from_dict(current_deployment_desc)

    def promote_to_main_orchestrator(self) -> None:
        """Update the deployment type of the current deployment desc."""
        if not (deployment_desc := self.deployment_desc()):
            return

        if deployment_desc.typ != DeploymentType.FAILOVER_ORCHESTRATOR:
            return

        deployment_desc.typ = DeploymentType.MAIN_ORCHESTRATOR
        deployment_desc.promotion_time = datetime.now().timestamp()
        self._charm.peers_data.put_object(
            Scope.APP, "deployment-description", deployment_desc.to_dict()
        )

    def demote_to_failover_orchestrator(self) -> None:
        """Update the deployment type of the current deployment desc."""
        if not (deployment_desc := self.deployment_desc()):
            return

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            return

        deployment_desc.typ = DeploymentType.FAILOVER_ORCHESTRATOR
        deployment_desc.promotion_time = None
        self._charm.peers_data.put_object(
            Scope.APP, "deployment-description", deployment_desc.to_dict()
        )

    def is_provider_orchestrator(self) -> bool:
        """Check whether the current app is an active provider orchestrator."""
        if not (deployment_desc := self.deployment_desc()):
            return False

        if deployment_desc.typ == DeploymentType.OTHER:
            return False

        if not self.is_peer_cluster_orchestrator_relation_set():
            return False

        if not (orchestrators := self._charm.peers_data.get_object(Scope.APP, "orchestrators")):
            return False

        orchestrators = PeerClusterOrchestrators.from_dict(orchestrators)
        return (
            (orchestrators.main_app and orchestrators.main_app.id == deployment_desc.app.id)
            or
            (orchestrators.failover_app and orchestrators.failover_app.id == deployment_desc.app.id)
        )

    def validate_roles(self, nodes: List[Node], on_new_unit: bool = False) -> None:
        """Validate full-cluster wide the quorum for CM/voting_only nodes on services start."""
        deployment_desc = self.deployment_desc()
        if not set(deployment_desc.config.roles) & {"cluster_manager", "voting_only"}:
            # the user is not adding any cm nor voting_only roles to the nodes
            return

        if deployment_desc.start == StartMode.WITH_GENERATED_ROLES:
            # the roles are automatically generated, we trust the correctness
            return

        # validate the full-cluster wide count of cm+voting_only nodes to keep the quorum
        full_cluster_planned_units = self._charm.app.planned_units()
        if self.is_peer_cluster_orchestrator_relation_set():
            if apps_in_fleet := self._charm.peers_data.get_object(Scope.APP, "cluster_fleet_apps"):
                apps_in_fleet = PeerClusterFleetApps.from_dict(apps_in_fleet)
                full_cluster_planned_units += sum(
                    [
                        p_cluster_app.planned_units
                        for p_cluster_app in apps_in_fleet.values()
                        if p_cluster_app.app.id != deployment_desc.app.id
                    ]
                )

        current_cluster_online_nodes = [
            node for node in nodes if node.app.id == deployment_desc.app.id
        ]

        if len(current_cluster_online_nodes) < full_cluster_planned_units - 1:
            # this is not the latest unit to be brought online, we can continue
            return

        voters = sum(1 for node in nodes if node.is_cm_eligible() or node.is_voting_only())
        if voters % 2 == (0 if on_new_unit else 1):
            # if validation called on new unit: it means it will start and maintain the quorum
            #    (called on the latest unit to be configured and brought online)
            # if validation called on existing cluster we should expect an odd number in the sum
            return

        raise OpenSearchProvidedRolesException(PClusterWrongNodesCountForQuorum)

    def is_peer_cluster_orchestrator_relation_set(self) -> bool:
        """Return whether the peer cluster relation is established."""
        orchestrators = PeerClusterOrchestrators.from_dict(
            self._charm.peers_data.get_object(Scope.APP, "orchestrators") or {}
        )
        if orchestrators.main_rel_id == -1:
            return False

        return (
            self._charm.model.get_relation(
                PeerClusterOrchestratorRelationName, orchestrators.main_rel_id
            )
            is not None
        )

    def rel_data(self) -> Optional[PeerClusterRelData]:
        """Return the peer cluster rel data if any."""
        if not self.is_peer_cluster_orchestrator_relation_set():
            return None

        orchestrators = PeerClusterOrchestrators.from_dict(
            self._charm.peers_data.get_object(Scope.APP, "orchestrators")
        )

        rel = self._charm.model.get_relation(
            PeerClusterOrchestratorRelationName, orchestrators.main_rel_id
        )
        return PeerClusterRelData.from_str(rel.data[rel.app].get("data"))

    def _pre_validate_roles_change(self, new_roles: List[str], prev_roles: List[str]):
        """Validate that the config changes of roles are allowed to happen."""
        if sorted(prev_roles) == sorted(new_roles):
            # nothing changed, leave
            return

        if not new_roles:
            # user requests the auto-generation logic of roles, this will have the
            # cluster_manager role generated, so nothing to validate
            return

        # if prev_roles None, means auto-generated roles, and will therefore include the cm role
        # for all the units up to the latest if even number of units, which will be voting_only
        prev_roles = set(prev_roles or ClusterTopology.generated_roles())
        new_roles = set(new_roles)

        if "cluster_manager" in new_roles and "voting_only" in new_roles:
            # Invalid combination of roles - we cannot have both roles set to a node
            raise OpenSearchProvidedRolesException(CmVoRolesProvidedInvalid)

        if "cluster_manager" in prev_roles and "cluster_manager" not in new_roles:
            # user requests a forbidden removal of "cluster_manager" role from node
            raise OpenSearchProvidedRolesException(CMRoleRemovalForbidden)

        if "data" in prev_roles and "data" not in new_roles:
            # this is dangerous as this might induce downtime + error on start when data on disk
            # we need to check if there are other sub-clusters with the data roles
            if not self.is_peer_cluster_orchestrator_relation_set():
                raise OpenSearchProvidedRolesException(DataRoleRemovalForbidden)

            # todo guarantee unicity of unit names on peer_relation_joined
            current_cluster_units = [
                format_unit_name(unit, app=self.deployment_desc().app)
                for unit in all_units(self._charm)
            ]
            all_nodes = ClusterTopology.nodes(
                self._charm.opensearch, self._opensearch.is_node_up(), self._charm.alt_hosts
            )
            other_clusters_data_nodes = [
                node
                for node in ClusterTopology.nodes_by_role(all_nodes)["data"]
                if node.name not in current_cluster_units
            ]
            if not other_clusters_data_nodes:
                raise OpenSearchProvidedRolesException(DataRoleRemovalForbidden)

    @staticmethod
    def _deployment_type(config: PeerClusterConfig, start_mode: StartMode) -> DeploymentType:
        """Check if the current cluster is an independent cluster."""
        has_cm_roles = (
            start_mode == StartMode.WITH_GENERATED_ROLES or "cluster_manager" in config.roles
        )
        if not has_cm_roles:
            return DeploymentType.OTHER

        return (
            DeploymentType.MAIN_ORCHESTRATOR
            if not config.init_hold
            else DeploymentType.FAILOVER_ORCHESTRATOR
        )
