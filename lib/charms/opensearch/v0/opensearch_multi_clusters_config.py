# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Setting configuration in opensearch config files."""
import logging
import shortuuid

from typing import List, Optional
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.models import Model
from charms.opensearch.v0.opensearch_internal_data import Scope

# The unique Charmhub library identifier, never change it
LIBID = "b02ab02d4fd644fdabe02c61e509093f"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class DeploymentType(BaseStrEnum):
    CLUSTER_MANAGER = "cluster-manager"
    CLUSTER_MANAGER_FAILOVER = "cluster-manager-failover"
    OTHER = "other"


class Directive(BaseStrEnum):
    WAIT_FOR_PEER_CLUSTER_RELATION = "wait-for-peer-cluster-relation"
    WAIT = "wait"
    START_WITH_PROVIDED_ROLES = "start-with-provided-roles"
    START_WITH_GENERATED_ROLES = "start-with-generated-roles"
    VALIDATE_CLUSTER_NAME = "validate-cluster-name"
    INHERIT_CLUSTER_NAME = "inherit-name"
    WELL_SETUP = "well-setup"
    RECONFIGURE = "reset-config"
    SHOW_STATUS = "show-status"
    NONE = "none"


class DeploymentState(BaseStrEnum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    BLOCKED_WAITING_FOR_RELATION = "blocked-waiting-for-peer-cluster-relation"
    BLOCKED_WRONG_RELATED_CLUSTER = "blocked-wrong-related-cluster"
    BLOCKED_CANNOT_START_WITH_ROLES = "blocked-cannot-start-with-current-set-roles"


class PeerClusterRelConfig(Model):

    def __init__(self, cluster_name: Optional[str], cm_nodes: List[str]):
        self.cluster_name = cluster_name
        self.cm_nodes = cm_nodes


class PeerClusterConfig(Model):

    def __init__(self, cluster_name: Optional[str], init_hold: bool, roles: List[str]):
        self.cluster_name = cluster_name
        self.init_hold = init_hold
        self.roles = roles


class DeploymentDescription(Model):

    def __init__(
        self,
        config: PeerClusterConfig,
        directives: List[Directive],
        state: DeploymentState = DeploymentState.ACTIVE,
        started: bool = False,
    ):
        self.config = config
        self.directives = directives
        self.state = state
        self.started = started


class OpenSearchPeerClustersManager:
    """This class covers the configuration changes depending on certain actions."""

    def __init__(self, charm):
        self._charm = charm

    def run(self, peer_cluster_rel_conf: Optional[PeerClusterRelConfig] = None) -> DeploymentDescription:
        """Updates and recomputes current peer cluster related config if applies."""
        # TODO pass config as a method attribute for when on_relation_joined conf inherited
        # TODO  and set directive accordingly
        if not self._charm.unit.is_leader():
            return

        user_config = PeerClusterConfig(
            cluster_name=self._charm.config.get("cluster_name"),
            init_hold=self._charm.config.get("init_hold", False),
            roles=[option.strip().lower() for option in self._charm.config.get("roles", "").split(",")]
        )

        current_deployment_desc = self._charm.peers_data.get_object(Scope.APP, "deployment-description")
        if current_deployment_desc:
            current_deployment_desc = DeploymentDescription.from_dict(current_deployment_desc)
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
            if not self._is_peer_cluster_rel_set():
                directives.append(Directive.SHOW_STATUS)
                deployment_state = DeploymentState.BLOCKED_WAITING_FOR_RELATION

            directives.extend([
                Directive.WAIT_FOR_PEER_CLUSTER_RELATION,
                Directive.VALIDATE_CLUSTER_NAME if config.cluster_name else Directive.INHERIT_CLUSTER_NAME,
                Directive.START_WITH_PROVIDED_ROLES if config.roles else Directive.START_WITH_GENERATED_ROLES,
            ])
            return DeploymentDescription(config, directives=directives, state=deployment_state)

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
            config=PeerClusterConfig(cluster_name, config.init_hold, config.roles),
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
        pass

    def _is_peer_cluster_rel_set(self) -> bool:
        return self._charm.model.get_relation(self.relation_name) is not None

    # TODO: on peer cluster relation broken --> delete deployment desc from databag

    def _validate_immutability(self):
        pass








