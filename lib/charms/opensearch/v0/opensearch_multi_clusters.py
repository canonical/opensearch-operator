# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Managing configuration related changes in multi cluster deployment context."""
import logging
from typing import List, Optional

import shortuuid
from charms.opensearch.v0.constants_charm import (
    PClusterNoRelation,
    PClusterWrongNodesCountForQuorum,
    PClusterWrongRelation,
    PClusterWrongRolesProvided,
    PeerClusterRelationName,
    PeerRelationName,
)
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.models import Model, Node
from charms.opensearch.v0.opensearch_exceptions import OpenSearchError
from charms.opensearch.v0.opensearch_internal_data import RelationDataStore, Scope
from ops import BlockedStatus

# The unique Charmhub library identifier, never change it
LIBID = "b02ab02d4fd644fdabe02c61e509093f"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OpenSearchProvidedRolesException(OpenSearchError):
    """Exception class for events when the user provided node roles will violate quorum."""


class DeploymentType(BaseStrEnum):
    """Nature of a sub cluster deployment."""

    CLUSTER_MANAGER = "cluster-manager"
    CLUSTER_MANAGER_FAILOVER = "cluster-manager-failover"
    OTHER = "other"


class Directive(BaseStrEnum):
    """Directive indicating what the pending actions for the current deployments are."""

    NONE = "none"
    SHOW_STATUS = "show-status"
    START_WITH_PROVIDED_ROLES = "start-with-provided-roles"
    START_WITH_GENERATED_ROLES = "start-with-generated-roles"
    WAIT_FOR_PEER_CLUSTER_RELATION = "wait-for-peer-cluster-relation"
    INHERIT_CLUSTER_NAME = "inherit-name"
    VALIDATE_CLUSTER_NAME = "validate-cluster-name"
    RECONFIGURE = "reconfigure-cluster"


class DeploymentState(BaseStrEnum):
    """State of a deployment, directly mapping to the juju statuses."""

    ACTIVE = "active"
    BLOCKED_WAITING_FOR_RELATION = "blocked-waiting-for-peer-cluster-relation"
    BLOCKED_WRONG_RELATED_CLUSTER = "blocked-wrong-related-cluster"
    BLOCKED_CANNOT_START_WITH_ROLES = "blocked-cannot-start-with-current-set-roles"


class PeerClusterRelDataCredentials(Model):
    """Model class for credentials passed on the PCluster relation."""

    # TODO: replace password by label."""
    admin_username: str
    admin_password: str


class PeerClusterRelData(Model):
    """Model class for the PCluster relation data."""

    cluster_name: Optional[str]
    cm_nodes: List[str]
    credentials: PeerClusterRelDataCredentials
    tls_ca: str


class PeerClusterConfig(Model):
    """Model class for the multi-clusters related config set by the user."""

    cluster_name: str
    init_hold: bool
    roles: List[str]


class DeploymentDescription(Model):
    """Model class describing the current state of a deployment / sub-cluster."""

    config: PeerClusterConfig
    directives: List[Directive]
    state: DeploymentState = DeploymentState.ACTIVE
    started: bool = False


class OpenSearchPeerClustersManager:
    """This class covers the configuration changes depending on certain actions."""

    def __init__(self, charm):
        self._charm = charm
        self._opensearch = charm.opensearch
        self.peer_cluster_data = RelationDataStore(self._charm, PeerClusterRelationName)

    def run(self, peer_cluster_rel_conf: Optional[PeerClusterRelData] = None) -> None:
        """Updates and recomputes current peer cluster related config if applies."""
        user_config = PeerClusterConfig(
            cluster_name=self._charm.config.get("cluster_name"),
            init_hold=self._charm.config.get("init_hold", False),
            roles=[
                option.strip().lower() for option in self._charm.config.get("roles", "").split(",")
            ],
        )

        current_deployment_desc = self.deployment_desc()
        if current_deployment_desc:
            self._pre_validate_roles_change(user_config, current_deployment_desc)
            deployment_desc = self._existing_cluster_setup(user_config, current_deployment_desc)
        else:
            deployment_desc = self._new_cluster_setup(user_config)

        # important to set as this is what we base our immutability checks on
        if current_deployment_desc != deployment_desc:
            self._charm.peers_data.put_object(
                Scope.APP, "deployment-description", deployment_desc.to_dict()
            )

    def _new_cluster_setup(self, config: PeerClusterConfig) -> DeploymentDescription:
        directives = []
        deployment_state = DeploymentState.ACTIVE
        if config.init_hold:
            if not self.peer_cluster_data.get_object("data"):  # todo check if relation is set
                directives.append(Directive.SHOW_STATUS)
                deployment_state = DeploymentState.BLOCKED_WAITING_FOR_RELATION

            directives.append(Directive.WAIT_FOR_PEER_CLUSTER_RELATION)
            directives.append(
                Directive.VALIDATE_CLUSTER_NAME
                if config.cluster_name
                else Directive.INHERIT_CLUSTER_NAME
            )
            directives.append(
                Directive.START_WITH_PROVIDED_ROLES
                if config.roles
                else Directive.START_WITH_GENERATED_ROLES
            )

            return DeploymentDescription(
                config=config, directives=directives, state=deployment_state
            )

        cluster_name = config.cluster_name
        if not cluster_name:
            cluster_name = f"{self._charm.app.name}-{shortuuid.ShortUUID().random(length=4)}"

        if not config.roles:
            directives.append(Directive.START_WITH_GENERATED_ROLES)
        elif "cluster_manager" in config.roles:
            directives.append(Directive.START_WITH_PROVIDED_ROLES)
        else:
            directives.extend([Directive.WAIT_FOR_PEER_CLUSTER_RELATION, Directive.SHOW_STATUS])
            deployment_state = DeploymentState.BLOCKED_CANNOT_START_WITH_ROLES

        return DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=cluster_name, init_hold=config.init_hold, roles=config.roles
            ),
            directives=directives,
            state=deployment_state,
        )

    def _existing_cluster_setup(
        self, config: PeerClusterConfig, prev_deployment: DeploymentDescription
    ) -> DeploymentDescription:
        # directives = []
        # deployment_state = DeploymentState.ACTIVE
        # if config.cluster_name !=
        # return DeploymentDescription()
        # TODO
        pass

    def can_start(self, deployment_desc: Optional[DeploymentDescription] = None) -> bool:
        """Return whether the service of a node can start."""
        deployment_desc = deployment_desc or self.deployment_desc()
        if not deployment_desc:
            return False

        blocking_directives = [
            Directive.WAIT_FOR_PEER_CLUSTER_RELATION,
            Directive.RECONFIGURE,
            Directive.VALIDATE_CLUSTER_NAME,
            Directive.INHERIT_CLUSTER_NAME,
        ]
        for directive in deployment_desc.directives:
            if directive in blocking_directives:
                return False

        return True

    def apply_status_if_needed(
        self, deployment_desc: Optional[DeploymentDescription] = None
    ) -> None:
        """Resolve and applies corresponding status from the deployment state."""
        deployment_desc = deployment_desc or self.deployment_desc()
        if not deployment_desc:
            return

        if Directive.SHOW_STATUS not in deployment_desc.directives:
            return

        blocked_statuses = {
            DeploymentState.BLOCKED_WAITING_FOR_RELATION: PClusterNoRelation,
            DeploymentState.BLOCKED_WRONG_RELATED_CLUSTER: PClusterWrongRelation,
            DeploymentState.BLOCKED_CANNOT_START_WITH_ROLES: PClusterWrongRolesProvided,
        }
        if deployment_desc.state not in blocked_statuses:
            for status in blocked_statuses.values():
                self._charm.status.clear(status)
            return

        self._charm.app.status = BlockedStatus(blocked_statuses[deployment_desc.state])

    def is_main_sub_cluster(self) -> bool:
        """Check if the current cluster is an independent cluster."""
        deployment_desc = self.deployment_desc()
        has_cm_roles = Directive.START_WITH_GENERATED_ROLES in deployment_desc.directives or (
            Directive.START_WITH_PROVIDED_ROLES in deployment_desc.directives
            and "cluster_manager" in deployment_desc.config.roles
        )
        return has_cm_roles and not deployment_desc.config.init_hold

    def deployment_desc(self) -> Optional[DeploymentDescription]:
        """Return the deployment description object if any."""
        current_deployment_desc = self._charm.peers_data.get_object(
            Scope.APP, "deployment-description"
        )
        if not current_deployment_desc:
            return None

        return DeploymentDescription.from_dict(current_deployment_desc)

    def validate_roles(self, nodes: List[Node]):
        """Validate full-cluster wide the quorum for CM/voting_only nodes on services start."""
        deployment_desc = self.deployment_desc()
        if not set(deployment_desc.config.roles or []) & {"cluster_manager", "voting_only"}:
            # the user is not adding any cm nor voting_only roles to the nodes
            return

        if Directive.START_WITH_PROVIDED_ROLES not in deployment_desc.directives:
            # the roles are automatically generated, we trust the correctness
            return

        # validate the full-cluster wide count of cm+voting_only nodes to keep the quorum
        current_cluster_planned_units = self._charm.app.planned_units
        current_cluster_units = [
            unit.name.replace("/", "-")
            for unit in self._charm.model.get_relation(PeerRelationName).units
        ]
        current_cluster_online_nodes = [
            node for node in nodes if node.name in current_cluster_units
        ]

        if len(current_cluster_online_nodes) < current_cluster_planned_units - 1:
            # this is not the latest unit to be brought online, we can continue
            return

        # this is the latest unit to be configured and brought online
        cms = sum(1 for node in nodes if node.is_cm_eligible())
        voting_only = sum(1 for node in nodes if node.is_voting_only())
        if (cms + voting_only) % 2 == 0:
            # the new unit to be started will maintain the quorum
            return

        raise OpenSearchProvidedRolesException(PClusterWrongNodesCountForQuorum)

    @staticmethod
    def _pre_validate_roles_change(
        config: PeerClusterConfig, prev_deployment: DeploymentDescription
    ):
        """Validate that the config changes of roles are allowed to happen."""
        if not config.roles:
            # user requests the auto-generation logic of roles, this will have the
            # cluster_manager role generated, so nothing to validate
            return

        # if prev_roles None, means auto-generated roles, and will therefore include the cm role
        # for all the units up to the latest if even number of units, which will be voting_only
        prev_roles = set(prev_deployment.config.roles or ["cluster_manager"])
        new_roles = set(config.roles)

        if "cluster_manager" in new_roles and "voting_only" in new_roles:
            # Invalid combination of roles - we cannot have both roles set to a node
            raise Exception

        if "cluster_manager" in prev_roles and "cluster_manager" not in new_roles:
            # user requests a forbidden removal of "cluster_manager" role from node
            raise Exception

    # TODO: register cluster as Cluster Manager in PEER _ RELATION _ DATA
    # TODO: on peer cluster relation broken --> delete deployment desc from databag
