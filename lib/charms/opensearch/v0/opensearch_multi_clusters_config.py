# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Setting configuration in opensearch config files."""
import enum
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



class DeploymentDescription:

    def __init__(
        self,
        init_hold: bool = False,
        cluster_name: Optional[str] = None,
        roles: Optional[List[str]] = None,
        state: DeploymentState = DeploymentState.ACTIVE,
        directive: Directive = Directive.WAIT,
        started: bool = False,
    ):
        self.cluster_name = cluster_name
        self.init_hold = init_hold
        self.directive = directive
        self.roles = roles
        self.started = started


class OpenSearchMultiClustersManager:
    """This class covers the configuration changes depending on certain actions."""

    def __init__(self, charm: CharmBase):
        self._charm = charm

    def update(self):
        """Updates and recomputes """

    def apply_config_if_needed(self) -> bool:
        """Apply multi clusters related config changes if applies."""
        # TODO pass config as a method attribute for when on_relation_joined conf inherited
        # TODO  and set directive accordingly
        cluster_name = self._charm.config.get("cluster_name")
        init_hold = self._charm.config.get("init_hold", False)
        roles = [option.strip().lower() for option in self._charm.config.get("roles", "").split(",")]

        deployment_desc = self._charm.peers_data.get_object(Scope.APP, "deployment-description")
        if deployment_desc:
            self._new_cluster_setup(cluster_name, init_hold, roles)
        else:
            self._existing_cluster_setup(init_hold, roles)

        if cluster_name and not init_hold:
            cluster_name = f"{self._charm.app.name}-{shortuuid.ShortUUID().random(length=4)}"
            directive = Directive.START


        self._charm.peers_data.put(Scope.APP, "deployment-directive", Directive.INHERIT_NAME)

    def _new_cluster_setup(self, cluster_name: Optional[str], init_hold: bool, roles: List[str]):
        if init_hold:

            return

        pass

    def _existing_cluster_setup(self, cluster_name: Optional[str], init_hold: bool, roles: List[str]):
        pass


    # def  _peer_cluster_directive(self):
