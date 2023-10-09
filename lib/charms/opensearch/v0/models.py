# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Cluster-related data structures / model classes."""
import json
from abc import ABC
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator, root_validator, Field

from charms.opensearch.v0.helper_enums import BaseStrEnum

# The unique Charmhub library identifier, never change it
LIBID = "6007e8030e4542e6b189e2873c8fbfef"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class Model(ABC, BaseModel):
    """Base model class."""

    def to_str(self) -> str:
        """Deserialize object into a string."""
        return self.json()

    def to_dict(self) -> Dict[str, Any]:
        """Deserialize object into a dict."""
        return self.dict()

    @classmethod
    def from_dict(cls, input_dict: Dict[str, Any]):
        """Create a new instance of this class from a json/dict repr."""
        return cls(**input_dict)

    @classmethod
    def from_str(cls, input_str_dict: str):
        """Create a new instance of this class from a stringified json/dict repr."""
        return cls.from_dict(json.loads(input_str_dict))

    def __eq__(self, other) -> bool:
        """Implement equality."""
        if other is None:
            return False

        equal = True
        for attr_key, attr_val in self.__dict__.items():
            other_attr_val = getattr(other, attr_key)
            if isinstance(attr_val, list):
                equal = equal and sorted(attr_val) == sorted(other_attr_val)
            else:
                equal = equal and (attr_val == other_attr_val)

        return equal


class Node(Model):
    """Data class representing a node in a cluster."""

    name: str
    roles: List[str]
    ip: str
    temperature: Optional[str] = None

    @classmethod
    @validator("roles")
    def roles_set(cls, v):
        """Returns deduplicated list of roles."""
        return list(set(v))

    def is_cm_eligible(self):
        """Returns whether this node is a cluster manager eligible member."""
        return "cluster_manager" in self.roles

    def is_voting_only(self):
        """Returns whether this node is a voting member."""
        return "voting_only" in self.roles

    def is_data(self):
        """Returns whether this node is a data* node."""
        for role in self.roles:
            if role.startswith("data"):
                return True

        return False


class DeploymentType(BaseStrEnum):
    """Nature of a sub cluster deployment."""

    MAIN_CLUSTER_MANAGER = "main-cluster-manager"
    CLUSTER_MANAGER_FAILOVER = "cluster-manager-failover"
    OTHER = "other"


class StartMode(BaseStrEnum):
    """Mode of start of units in this deployment."""

    WITH_PROVIDED_ROLES = "start-with-provided-roles"
    WITH_GENERATED_ROLES = "start-with-generated-roles"


class Directive(BaseStrEnum):
    """Directive indicating what the pending actions for the current deployments are."""

    NONE = "none"
    SHOW_STATUS = "show-status"
    WAIT_FOR_PEER_CLUSTER_RELATION = "wait-for-peer-cluster-relation"
    INHERIT_CLUSTER_NAME = "inherit-name"
    VALIDATE_CLUSTER_NAME = "validate-cluster-name"
    RECONFIGURE = "reconfigure-cluster"


class State(BaseStrEnum):
    """State of a deployment, directly mapping to the juju statuses."""

    ACTIVE = "active"
    BLOCKED_WAITING_FOR_RELATION = "blocked-waiting-for-peer-cluster-relation"
    BLOCKED_WRONG_RELATED_CLUSTER = "blocked-wrong-related-cluster"
    BLOCKED_CANNOT_START_WITH_ROLES = "blocked-cannot-start-with-current-set-roles"
    BLOCKED_CANNOT_APPLY_NEW_ROLES = "blocked-cannot-apply-new-roles"


class DeploymentState(Model):
    """Full state of a deployment, along with the juju status."""

    value: State
    message: str = Field(default="")

    @root_validator
    def prevent_none(cls, values):
        if values["value"] == State.ACTIVE:
            values["message"] = ""
        elif not values["message"].strip():
            raise ValueError("The message must be set when state not Active.")

        return values


class PeerClusterRelDataCredentials(Model):
    """Model class for credentials passed on the PCluster relation."""

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
    data_temperature: Optional[str] = None

    @root_validator
    def set_node_temperature(cls, values):
        allowed_temps = ["hot", "warm", "cold", "frozen"]

        input_temps = set()
        for role in values["roles"]:
            if not role.startswith("data."):
                continue

            temp = role.split(".")[1]
            if temp not in allowed_temps:
                raise ValueError(f"data.'{temp}' not allowed. Allowed values: {allowed_temps}")

            input_temps.add(temp)

        if len(input_temps) > 1:
            raise ValueError("More than 1 data temperature provided.")
        elif input_temps:
            temperature = input_temps.pop()
            values["data_temperature"] = temperature

            values["roles"].append("data")
            values["roles"].remove(f"data.{temperature}")
            values["roles"] = list(set(values["roles"]))

        return values


class DeploymentDescription(Model):
    """Model class describing the current state of a deployment / sub-cluster."""

    config: PeerClusterConfig
    start: StartMode
    directives: List[Directive]
    typ: DeploymentType
    state: DeploymentState = DeploymentState(value=State.ACTIVE)
