# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Managing simple or large deployments and configuration related changes."""
import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, List, Literal, Optional

from charms.opensearch.v0.constants_charm import (
    AdminUser,
    CMRoleRemovalForbidden,
    CmVoRolesProvidedInvalid,
    COSUser,
    DataRoleRemovalForbidden,
    KibanaserverUser,
    PClusterNoRelation,
    PClusterWrongNodesCountForQuorum,
    PClusterWrongRelation,
    PClusterWrongRolesProvided,
    PeerClusterOrchestratorRelationName,
    PeerClusterRelationName,
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
    PeerClusterApp,
    PeerClusterConfig,
    PeerClusterOrchestrators,
    PeerClusterRelData,
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
        logger.debug("Running peer cluster manager run function")
        user_config = self._user_config()
        if not (current_deployment_desc := self.deployment_desc()):
            # new cluster
            deployment_desc = self._new_cluster_setup(user_config)
            logger.debug("New deployment_desc from new cluster setup: %s", deployment_desc)
            self._charm.peers_data.put_object(
                Scope.APP, "deployment-description", deployment_desc.to_dict()
            )
            self.apply_status_if_needed(deployment_desc)
            return

        # update cluster deployment desc
        logger.debug("Existing deployment_desc before cluster setup: %s", current_deployment_desc)
        deployment_desc = self._existing_cluster_setup(user_config, current_deployment_desc)
        logger.debug("Existing deployment_desc after cluster setup: %s", deployment_desc)
        if current_deployment_desc == deployment_desc:
            return

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

    def run_with_relation_data(self, data: PeerClusterRelData) -> None:  # noqa: C901
        """Update current peer cluster related config based on peer_cluster rel_data."""
        logger.debug("running with relation data")
        current_deployment_desc = self.deployment_desc()

        config = current_deployment_desc.config
        deployment_state = current_deployment_desc.state
        pending_directives = current_deployment_desc.pending_directives

        logger.debug("deployment_desc; %s", current_deployment_desc)

        if Directive.WAIT_FOR_PEER_CLUSTER_RELATION in pending_directives:
            logger.debug("clearing WAIT_FOR_PEER_CLUSTER_RELATION directive")
            pending_directives.remove(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)
            if deployment_state.value == State.BLOCKED_WAITING_FOR_RELATION:
                deployment_state = DeploymentState(value=State.ACTIVE)

        if Directive.VALIDATE_CLUSTER_NAME in pending_directives:
            if config.cluster_name != data.cluster_name:
                deployment_state = DeploymentState(
                    value=State.BLOCKED_WRONG_RELATED_CLUSTER, message=PClusterWrongRelation
                )
            elif deployment_state.value in [
                State.BLOCKED_WRONG_RELATED_CLUSTER,
                State.BLOCKED_WAITING_FOR_RELATION,
                State.ACTIVE,
            ]:
                deployment_state = DeploymentState(value=State.ACTIVE)
                pending_directives.remove(Directive.VALIDATE_CLUSTER_NAME)
        elif Directive.INHERIT_CLUSTER_NAME in pending_directives:
            config.cluster_name = data.cluster_name
            pending_directives.remove(Directive.INHERIT_CLUSTER_NAME)
            if deployment_state.value == State.BLOCKED_WAITING_FOR_RELATION:
                deployment_state = DeploymentState(value=State.ACTIVE)

        pending_directives.append(Directive.SHOW_STATUS)
        new_deployment_desc = DeploymentDescription(
            app=current_deployment_desc.app,
            config=config,
            pending_directives=pending_directives,
            typ=current_deployment_desc.typ,
            state=deployment_state,
            start=current_deployment_desc.start,
            cluster_name_autogenerated=data.deployment_desc.cluster_name_autogenerated,
        )

        logger.debug("new_deployment_desc: %s", new_deployment_desc)
        self._charm.peers_data.put_object(
            Scope.APP, "deployment-description", new_deployment_desc.to_dict()
        )

        # append in the current app the CM nodes reported from the relation
        self._charm.peers_data.put_object(
            scope=Scope.APP,
            key="nodes_config",
            value=dict(sorted({node.name: node.to_dict() for node in data.cm_nodes}.items())),
            merge=True,
        )
        self._charm.opensearch_config.add_seed_hosts([node.ip for node in data.cm_nodes])

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
            profile=self._charm.performance_profile.current.typ.value,
        )

    def _new_cluster_setup(self, config: PeerClusterConfig) -> DeploymentDescription:
        """Build deployment description of a new cluster."""
        logger.debug("New cluster setup")
        directives = []
        deployment_state = DeploymentState(value=State.ACTIVE)
        if config.init_hold:
            # checks if peer cluster relation is set
            if not self._charm.model.relations[PeerClusterRelationName]:
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

        cluster_name_autogenerated = False
        if not (cluster_name := config.cluster_name.strip()):
            cluster_name = f"{self._charm.app.name}-{ShortUUID().random(length=4)}".lower()
            cluster_name_autogenerated = True

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
                profile=self._charm.performance_profile.current.typ.value,
            ),
            start=start_mode,
            pending_directives=directives,
            typ=self._deployment_type(config, start_mode),
            state=deployment_state,
            cluster_name_autogenerated=cluster_name_autogenerated,
        )

    def _existing_cluster_setup(
        self, config: PeerClusterConfig, prev_deployment: DeploymentDescription
    ) -> DeploymentDescription:
        """Build deployment description of an existing (started or not) cluster."""
        logger.debug(
            "Found deployment description using existing cluster setup. deployment desc: %s",
            prev_deployment,
        )
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

        deployment_type = self._deployment_type(config, start_mode, prev_deployment.typ)
        return DeploymentDescription(
            app=prev_deployment.app,
            config=PeerClusterConfig(
                cluster_name=prev_deployment.config.cluster_name,
                init_hold=prev_deployment.config.init_hold,
                roles=config.roles,
                data_temperature=config.data_temperature,
                profile=self._charm.performance_profile.current.typ.value,
            ),
            start=start_mode,
            state=deployment_state,
            typ=deployment_type,
            pending_directives=list(set(directives)),
            cluster_name_autogenerated=prev_deployment.cluster_name_autogenerated,
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
        logger.debug("Directives: %s", deployment_desc.pending_directives)
        for directive in deployment_desc.pending_directives:
            if directive in blocking_directives:
                logger.debug("blocking directive %s", directive)
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
        logger.debug("Clearing directive %s. DeploymentDesc: %s", directive, deployment_desc)
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

    def promote_deployment_type(self) -> None:
        """Update the deployment type of the current deployment desc."""
        if not (deployment_desc := self.deployment_desc()):
            return

        if deployment_desc.typ != DeploymentType.FAILOVER_ORCHESTRATOR:
            return

        logger.debug("Promoting deployment type to MAIN_ORCHESTRATOR")
        deployment_desc.typ = DeploymentType.MAIN_ORCHESTRATOR
        deployment_desc.promotion_time = datetime.now().timestamp()
        logger.debug("New deployment description: %s", deployment_desc)
        if Directive.WAIT_FOR_PEER_CLUSTER_RELATION in deployment_desc.pending_directives:
            deployment_desc.pending_directives.remove(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)
            if deployment_desc.state.value == State.BLOCKED_WAITING_FOR_RELATION:
                deployment_desc.state = DeploymentState(value=State.ACTIVE)
        deployment_desc.pending_directives.append(Directive.SHOW_STATUS)
        self._charm.peers_data.put_object(
            Scope.APP, "deployment-description", deployment_desc.to_dict()
        )

    def demote_deployment_type(self) -> None:
        """Update the deployment type of the current deployment desc."""
        if not (deployment_desc := self.deployment_desc()):
            return

        if deployment_desc.typ != DeploymentType.MAIN_ORCHESTRATOR:
            return

        deployment_desc.typ = DeploymentType.FAILOVER_ORCHESTRATOR
        deployment_desc.promotion_time = None
        logger.debug("Demoting deployment type to FAILOVER_ORCHESTRATOR: %s", deployment_desc)
        deployment_desc.state = DeploymentState(
            value=State.BLOCKED_WAITING_FOR_RELATION, message=PClusterNoRelation
        )
        deployment_desc.pending_directives.append(Directive.SHOW_STATUS)
        deployment_desc.pending_directives.append(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)
        self._charm.peers_data.put_object(
            Scope.APP, "deployment-description", deployment_desc.to_dict()
        )
        self._charm.peer_cluster_provider.clean_all_relation_data()

    def has_recommended_cm_count(self, nodes: List[Node]) -> bool:
        """Validate cluster-wide count for CM-eligible nodes is at least 3"""
        deployment_desc = self.deployment_desc()
        if (
            not set(deployment_desc.config.roles) & {"cluster_manager", "voting_only"}
            and deployment_desc.start != StartMode.WITH_GENERATED_ROLES
        ):
            # only CM-eligible nodes run the validations
            return True

        is_large_deployment = self.is_provider() or self.is_consumer()
        cms = sum(1 for node in nodes if node.is_cm_eligible())
        if not is_large_deployment or (is_large_deployment and cms >= 3):
            # validation is only needed in large deployments
            # we can start with any number of cms but set a blocked status
            # if CMS < 3 when a CM-eligible application is scaled down or removed
            return True

        logger.info("Less than 3 CM-eligible units in this cluster")
        return False

    def validate_recommended_cm_unit_count(self, nodes: Optional[List[Node]] = None) -> None:
        """Validates that the cluster has at least 3 CM-eligible units.

        If validation fails, sets the application status to Blocked.
        """
        if nodes is None:
            nodes = ClusterTopology.nodes(
                self._charm.opensearch, self._opensearch.is_node_up(), self._charm.alt_hosts
            )

        if self.has_recommended_cm_count(nodes):
            self._charm.peers_data.delete(Scope.APP, "is_expecting_cm_unit")
            self._charm.status.clear(PClusterWrongNodesCountForQuorum, app=True)
            return

        self._charm.peers_data.put(Scope.APP, "is_expecting_cm_unit", True)
        self._charm.status.set(BlockedStatus(PClusterWrongNodesCountForQuorum), app=True)

    def apps_in_fleet(self) -> List[PeerClusterApp]:
        """Returns list of apps in cluster fleet"""
        cluster_fleet_apps = (
            self._charm.peers_data.get_object(Scope.APP, "cluster_fleet_apps") or {}
        )
        return [PeerClusterApp.from_dict(app) for app in cluster_fleet_apps.values()]

    def is_provider(self, typ: Optional[Literal["main", "failover"]] = None) -> bool:
        """Return whether the current app is a related to provider / orchestrator."""
        if not (deployment_desc := self.deployment_desc()):
            return False

        if deployment_desc.typ == DeploymentType.OTHER:
            return False

        # the current app is not related as an orchestrator to any app
        if not self._charm.model.relations[PeerClusterOrchestratorRelationName]:
            return False

        # check if the current app is elected orchestrator
        if not (orchestrators := self._charm.peers_data.get_object(Scope.APP, "orchestrators")):
            # not populated yet
            return False

        current_app_id = deployment_desc.app.id
        orchestrators = PeerClusterOrchestrators.from_dict(orchestrators)

        is_main = orchestrators.main_app and orchestrators.main_app.id == current_app_id
        is_failover = (
            orchestrators.failover_app and orchestrators.failover_app.id == current_app_id
        )

        if typ == "main":
            return is_main
        elif typ == "failover":
            return is_failover
        else:
            return is_main or is_failover

    def is_consumer(self, of: Optional[Literal["main", "failover"]] = None) -> bool:
        """Check if the current app is a consumer of the peer-cluster-relation."""
        if not (deployment_desc := self.deployment_desc()):
            return False

        # the current app is not related to any orchestrator app
        if not self._charm.model.relations[PeerClusterRelationName]:
            return False

        # check if the current app is elected orchestrator
        if not (orchestrators := self._charm.peers_data.get_object(Scope.APP, "orchestrators")):
            # not populated yet
            return False

        orchestrators = PeerClusterOrchestrators.from_dict(orchestrators)
        if orchestrators.main_app and orchestrators.main_app.id == deployment_desc.app.id:
            # there is a wrong relation happening - where current is the main orchestrator
            # yet related to another "orchestrator"
            return False

        of_main = (
            orchestrators.main_app
            and self._charm.model.get_relation(
                PeerClusterOrchestratorRelationName, orchestrators.main_rel_id
            )
            is not None
        )
        of_failover = (
            orchestrators.failover_app
            and self._charm.model.get_relation(
                PeerClusterOrchestratorRelationName, orchestrators.failover_rel_id
            )
            is not None
        )
        if of == "main":
            return of_main
        elif of == "failover":
            return of_failover
        else:
            return of_main or of_failover

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

    def rel_data(self, peek_secrets: bool = False) -> Optional[PeerClusterRelData]:
        """Return the peer cluster rel data if any."""
        if not self.is_consumer(of="main"):
            return None

        orchestrators = PeerClusterOrchestrators.from_dict(
            self._charm.peers_data.get_object(Scope.APP, "orchestrators")
        )

        rel = self._charm.model.get_relation(
            PeerClusterOrchestratorRelationName, orchestrators.main_rel_id
        )
        if not (data := rel.data[rel.app].get("data")):
            return None

        if peek_secrets:
            return self.rel_data_from_str_and_peek_secrets(data)
        return self.rel_data_from_str(data)

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
            if not self.is_consumer():
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
    def _deployment_type(
        config: PeerClusterConfig,
        start_mode: StartMode,
        prev_deployment_type: Optional[DeploymentType] = None,
    ) -> DeploymentType:
        """Check if the current cluster is an independent cluster."""
        has_cm_roles = (
            start_mode == StartMode.WITH_GENERATED_ROLES or "cluster_manager" in config.roles
        )
        if not has_cm_roles:
            return DeploymentType.OTHER

        return prev_deployment_type or (
            DeploymentType.MAIN_ORCHESTRATOR
            if not config.init_hold
            else DeploymentType.FAILOVER_ORCHESTRATOR
        )

    def rel_data_from_str_and_peek_secrets(self, redacted_dict_str: str) -> PeerClusterRelData:
        """Construct the peer cluster rel data from the secret data."""
        content = json.loads(redacted_dict_str)
        credentials = content["credentials"]

        credentials["admin_password"] = (
            self._charm.model.get_secret(id=credentials["admin_password"])
            .peek_content()
            .get(self._charm.secrets.password_key(AdminUser))
        )

        credentials["admin_password_hash"] = (
            self._charm.model.get_secret(id=credentials["admin_password_hash"])
            .peek_content()
            .get(self._charm.secrets.hash_key(AdminUser))
        )

        credentials["kibana_password"] = (
            self._charm.model.get_secret(id=credentials["kibana_password"])
            .peek_content()
            .get(self._charm.secrets.password_key(KibanaserverUser))
        )

        credentials["kibana_password_hash"] = (
            self._charm.model.get_secret(id=credentials["kibana_password_hash"])
            .peek_content()
            .get(self._charm.secrets.hash_key(KibanaserverUser))
        )

        if "monitor_password" in credentials:
            credentials["monitor_password"] = (
                self._charm.model.get_secret(id=credentials["monitor_password"])
                .peek_content()
                .get(self._charm.secrets.password_key(COSUser))
            )

        if "admin_tls" in credentials:
            credentials["admin_tls"] = self._charm.model.get_secret(
                id=credentials["admin_tls"]
            ).peek_content()

        if (
            "s3" in credentials
            and credentials["s3"].get("access-key")
            and credentials["s3"].get("secret-key")
        ):
            credentials["s3"]["access-key"] = (
                self._charm.model.get_secret(id=credentials["s3"]["access-key"])
                .peek_content()
                .get("s3-access-key")
            )
            credentials["s3"]["secret-key"] = (
                self._charm.model.get_secret(id=credentials["s3"]["secret-key"])
                .peek_content()
                .get("s3-secret-key")
            )
        if (
            "azure" in credentials
            and credentials["azure"].get("storage-account")
            and credentials["azure"].get("secret-key")
        ):
            credentials["azure"]["storage-account"] = (
                self._charm.model.get_secret(id=credentials["azure"]["storage-account"])
                .peek_content()
                .get("azure-storage-account")
            )
            credentials["azure"]["secret-key"] = (
                self._charm.model.get_secret(id=credentials["azure"]["secret-key"])
                .peek_content()
                .get("azure-secret-key")
            )
        return PeerClusterRelData.from_dict(content)

    def _resolve_credential(
        self,
        credential: str,
        *,
        content_key: Optional[str] = None,
        password_key: Optional[str] = None,
        hash_key: Optional[str] = None,
    ):
        """Resolves credential to its secret value if it's a secret"""
        if not credential.startswith("secret://"):
            return credential

        if not content_key:
            if password_key:
                content_key = self._charm.secrets.password_key(password_key)
            elif hash_key:
                content_key = self._charm.secrets.hash_key(hash_key)
            else:
                raise ValueError("One of content_key, password_key or hash_key must be provided.")
        return self._charm.model.get_secret(id=credential).get_content().get(content_key)

    def rel_data_from_str(self, redacted_dict_str: str) -> PeerClusterRelData:
        """Construct the peer cluster rel data from the secret data."""
        content = json.loads(redacted_dict_str)
        credentials = content["credentials"]

        credentials["admin_password"] = self._resolve_credential(
            credentials["admin_password"], password_key=AdminUser
        )
        credentials["admin_password_hash"] = self._resolve_credential(
            credentials["admin_password_hash"], hash_key=AdminUser
        )

        credentials["kibana_password"] = self._resolve_credential(
            credentials["kibana_password"], password_key=KibanaserverUser
        )
        credentials["kibana_password_hash"] = self._resolve_credential(
            credentials["kibana_password_hash"], hash_key=KibanaserverUser
        )

        if credentials.get("monitor_password"):
            credentials["monitor_password"] = self._resolve_credential(
                credentials["monitor_password"], password_key=COSUser
            )

        if credentials.get("admin_tls") and isinstance(credentials["admin_tls"], str):
            credentials["admin_tls"] = self._charm.model.get_secret(
                id=credentials["admin_tls"]
            ).get_content()

        if (
            credentials.get("s3")
            and credentials["s3"].get("access-key")
            and credentials["s3"].get("secret-key")
        ):
            credentials["s3"]["access-key"] = self._resolve_credential(
                credentials["s3"]["access-key"], content_key="s3-access-key"
            )
            credentials["s3"]["secret-key"] = self._resolve_credential(
                credentials["s3"]["secret-key"], content_key="s3-secret-key"
            )
        if (
            credentials.get("azure")
            and credentials["azure"].get("storage-account")
            and credentials["azure"].get("secret-key")
        ):
            credentials["azure"]["storage-account"] = self._resolve_credential(
                credentials["azure"]["storage-account"], content_key="azure-storage-account"
            )
            credentials["azure"]["secret-key"] = self._resolve_credential(
                credentials["azure"]["secret-key"], content_key="azure-secret-key"
            )

        return PeerClusterRelData.from_dict(content)
