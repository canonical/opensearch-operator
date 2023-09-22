# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Setting configuration in opensearch config files."""
import enum
import json
import logging
import socket
from typing import Dict, List, Optional

import shortuuid
from ops import Object, CharmBase

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.helper_security import normalized_tls_subject
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_internal_data import Scope

# The unique Charmhub library identifier, never change it
LIBID = "b02ab02d4fd644fdabe02c61e509093f"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class Directive(BaseStrEnum):
    WAIT_FOR_PEER_CLUSTER_RELATION = "wait-for-peer-cluster-relation"
    WAIT = "wait"
    START = "start"
    INHERIT_NAME = "inherit-name"
    WELL_SETUP = "well-setup"


class DeploymentState(BaseStrEnum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    BLOCKED_WAITING_FOR_RELATION = "blocked-waiting-for-peer-cluster-relation"
    BLOCKED_WRONG_RELATED_CLUSTER = "blocked-wrong-related-cluster"
    BLOCKED_CANNOT_START_WITH_ROLES = "blocked-cannot-start-with-current-set-roles"


class PeerClusterConfig:

    def __init__(self, cluster_name: Optional[str], init_hold: bool, roles: List[str]):
        self.cluster_name = cluster_name
        self.init_hold = init_hold
        self.roles = roles


class DeploymentDescription:

    def __init__(
        self,
        config: PeerClusterConfig,
        state: DeploymentState = DeploymentState.ACTIVE,
        directive: Directive = Directive.WAIT,
        started: bool = False,
    ):
        self.config = config
        self.state = state
        self.directive = directive
        self.started = started

    def update(self, config: PeerClusterConfig, directive: Directive):
        """Update the cluster config and directive."""
        self.config = config
        self.directive = directive

    @staticmethod
    def from_dict(input_dict):
        """Create a new instance of this class from a json/dict repr."""
        return DeploymentDescription(
            input_dict["config"],
            input_dict.get("state", DeploymentState.ACTIVE),
            input_dict.get("directive", Directive.WAIT),
            input_dict.get("started", False),
        )

    @staticmethod
    def from_str(input_str_dict):
        """Create a new instance of this class from a stringified json/dict repr."""
        return DeploymentDescription.from_dict(json.loads(input_str_dict))


class OpenSearchPeerClustersManager:
    """This class covers the configuration changes depending on certain actions."""

    def __init__(self, charm):
        self._charm = charm

    def run(self) -> None:
        """Updates and recomputes current peer cluster related config if applies."""
        # TODO pass config as a method attribute for when on_relation_joined conf inherited
        # TODO  and set directive accordingly
        if not self._charm.unit.is_leader():
            return

        config = PeerClusterConfig(
            cluster_name=self._charm.config.get("cluster_name"),
            init_hold=self._charm.config.get("init_hold", False),
            roles=[option.strip().lower() for option in self._charm.config.get("roles", "").split(",")]
        )

        deployment_desc = self._charm.peers_data.get_object(Scope.APP, "deployment-description")
        if deployment_desc:
            deployment_desc = DeploymentDescription.from_dict(deployment_desc)
            directive = self._existing_cluster_setup(config, deployment_desc)
        else:
            deployment_desc = DeploymentDescription(config)
            directive = self._new_cluster_setup(config)

        deployment_desc.update(config, directive)
        self._charm.peers_data.put(Scope.APP, "deployment-description", json.dumps(deployment_desc))

    def _new_cluster_setup(self, config: PeerClusterConfig) -> Directive:
        cluster_name = self._charm.config.get("cluster_name")
        if config.init_hold:
            directive = Directive.WAIT_FOR_PEER_CLUSTER_RELATION
        else:
            cluster_name = f"{self._charm.app.name}-{shortuuid.ShortUUID().random(length=4)}"

        pass

    def _existing_cluster_setup(self, config: PeerClusterConfig, prev_deployment_desc: DeploymentDescription) -> Directive:
        pass





















"""
# def  _peer_cluster_directive(self):
def apply_config_if_needed(self) -> bool:
        #Apply multi clusters related config changes if applies.

        if cluster_name and not init_hold:
            cluster_name = f"{self._charm.app.name}-{shortuuid.ShortUUID().random(length=4)}"
            directive = Directive.START


        self._charm.peers_data.put(Scope.APP, "deployment-directive", Directive.INHERIT_NAME)

"""