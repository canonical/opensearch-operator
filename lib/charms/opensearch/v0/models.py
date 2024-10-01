# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Cluster-related data structures / model classes."""
import json
import math
from abc import ABC
from datetime import datetime
from enum import Enum
from hashlib import md5
from typing import Any, Dict, List, Literal, Optional, Tuple

from charms.opensearch.v0.helper_enums import BaseStrEnum
from pydantic import BaseModel, Field, root_validator, validator
from pydantic.utils import ROOT_KEY

# The unique Charmhub library identifier, never change it
LIBID = "6007e8030e4542e6b189e2873c8fbfef"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class Model(ABC, BaseModel):
    """Base model class."""

    def __init__(self, **data: Any) -> None:
        if self.__custom_root_type__ and data.keys() != {ROOT_KEY}:
            data = {ROOT_KEY: data}
        super().__init__(**data)

    def to_str(self, by_alias: bool = False) -> str:
        """Deserialize object into a string."""
        return json.dumps(Model.sort_payload(self.to_dict(by_alias=by_alias)))

    def to_dict(self, by_alias: bool = False) -> Dict[str, Any]:
        """Deserialize object into a dict."""
        return self.dict(by_alias=by_alias)

    @classmethod
    def from_dict(cls, input_dict: Optional[Dict[str, Any]]):
        """Create a new instance of this class from a json/dict repr."""
        if not input_dict:  # to handle when classes defined defaults
            return cls()
        return cls(**input_dict)

    @classmethod
    def from_str(cls, input_str_dict: str):
        """Create a new instance of this class from a stringified json/dict repr."""
        return cls.parse_raw(input_str_dict)

    @staticmethod
    def sort_payload(payload: any) -> any:
        """Sort input payloads to avoid rel-changed events for same unordered objects."""
        if isinstance(payload, dict):
            # Sort dictionary by keys
            return {key: Model.sort_payload(value) for key, value in sorted(payload.items())}
        elif isinstance(payload, list):
            # Sort each item in the list and then sort the list
            sorted_list = [Model.sort_payload(item) for item in payload]
            try:
                return sorted(sorted_list)
            except TypeError:
                # If items are not sortable, return as is
                return sorted_list
        else:
            # Return the value as is for non-dict, non-list types
            return payload

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


class App(Model):
    """Data class representing an application."""

    id: Optional[str] = None
    short_id: Optional[str] = None
    name: Optional[str] = None
    model_uuid: Optional[str] = None

    @root_validator
    def set_props(cls, values):  # noqa: N805
        """Generate the attributes depending on the input."""
        if None not in list(values.values()):
            return values

        if not values["id"] and None in [values["name"], values["model_uuid"]]:
            raise ValueError("'id' or 'name and model_uuid' must be set.")

        if values["id"]:
            full_id_split = values["id"].split("/")
            values["name"], values["model_uuid"] = full_id_split[-1], full_id_split[0]
        else:
            values["id"] = f"{values['model_uuid']}/{values['name']}"

        values["short_id"] = md5(values["id"].encode()).hexdigest()[:3]
        return values


class Node(Model):
    """Data class representing a node in a cluster."""

    name: str
    roles: List[str]
    ip: str
    app: App
    unit_number: int
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

    MAIN_ORCHESTRATOR = "main-orchestrator"
    FAILOVER_ORCHESTRATOR = "failover-orchestrator"
    OTHER = "other"


class PerformanceType(BaseStrEnum):
    """Performance types available."""

    PRODUCTION = "production"
    STAGING = "staging"
    TESTING = "testing"


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
    def prevent_none(cls, values):  # noqa: N805
        """Validate the message or lack of depending on the state."""
        if values["value"] == State.ACTIVE:
            values["message"] = ""
        elif not values["message"].strip():
            raise ValueError("The message must be set when state not Active.")

        return values


class PeerClusterConfig(Model):
    """Model class for the multi-clusters related config set by the user."""

    cluster_name: str
    init_hold: bool
    roles: List[str]
    data_temperature: Optional[str] = None

    @root_validator
    def set_node_temperature(cls, values):  # noqa: N805
        """Set and validate the node temperature."""
        allowed_temps = ["hot", "warm", "cold", "frozen", "content"]

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

    app: App
    config: PeerClusterConfig
    start: StartMode
    pending_directives: List[Directive]
    typ: DeploymentType
    state: DeploymentState = DeploymentState(value=State.ACTIVE)
    promotion_time: Optional[float]

    @root_validator
    def set_promotion_time(cls, values):  # noqa: N805
        """Set promotion time of a failover to a main CM."""
        if not values["promotion_time"] and values["typ"] == DeploymentType.MAIN_ORCHESTRATOR:
            values["promotion_time"] = datetime.now().timestamp()

        return values


class S3RelDataCredentials(Model):
    """Model class for credentials passed on the PCluster relation."""

    access_key: str = Field(alias="access-key")
    secret_key: str = Field(alias="secret-key")

    class Config:
        """Model config of this pydantic model."""

        allow_population_by_field_name = True


class PeerClusterRelDataCredentials(Model):
    """Model class for credentials passed on the PCluster relation."""

    admin_username: str
    admin_password: str
    admin_password_hash: str
    kibana_password: str
    kibana_password_hash: str
    monitor_password: Optional[str]
    admin_tls: Optional[Dict[str, Optional[str]]]
    s3: Optional[S3RelDataCredentials]


class PeerClusterApp(Model):
    """Model class for representing an application part of a large deployment."""

    app: App
    planned_units: int
    units: List[str]
    roles: List[str]


class PeerClusterFleetApps(Model):
    """Model class for all applications in a large deployment as a dict."""

    __root__: Dict[str, PeerClusterApp]

    def __iter__(self):
        """Implements the iter magic method."""
        return iter(self.__root__)

    def __getitem__(self, item):
        """Implements the getitem magic method."""
        return self.__root__[item]


class PeerClusterRelData(Model):
    """Model class for the PCluster relation data."""

    cluster_name: str
    cm_nodes: List[Node]
    credentials: PeerClusterRelDataCredentials
    deployment_desc: Optional[DeploymentDescription]


class PeerClusterRelErrorData(Model):
    """Model class for the PCluster relation data."""

    cluster_name: Optional[str]
    should_sever_relation: bool
    should_wait: bool
    blocked_message: str
    deployment_desc: Optional[DeploymentDescription]


class PeerClusterOrchestrators(Model):
    """Model class for the PClusters registered main/failover clusters."""

    _TYPES = Literal["main", "failover"]

    main_rel_id: int = -1
    main_app: Optional[App]
    failover_rel_id: int = -1
    failover_app: Optional[App]

    def delete(self, typ: _TYPES) -> None:
        """Delete an orchestrator from the current pair."""
        if typ == "main":
            self.main_rel_id = -1
            self.main_app = None
        else:
            self.failover_rel_id = -1
            self.failover_app = None

    def promote_failover(self) -> None:
        """Delete previous main orchestrator and promote failover if any."""
        self.main_app = self.failover_app
        self.main_rel_id = self.failover_rel_id
        self.delete("failover")


class ByteUnit(Enum):
    """As per docs, Java uses the byte format.

    Converts the *B and *iB to the same raw values. For example, can be written as:
    - 6m: 6 * 1024 * 1024
    - 6144k: 6144 * 1024
    - 6291456: 6291456 bytes

    More info: https://dev.java/learn/jvm/tools/core/java/#overview
    """

    B = 1  # noqa: N815
    kB = 1024  # noqa: N815
    mB = 1024 * kB  # noqa: N815
    gB = 1024 * mB  # noqa: N815

    @staticmethod
    def get(name: str) -> int:
        """Convert the value to the required unit."""
        val = name.lower()
        if val == "kb" or val == "k":
            return ByteUnit.kB
        if val == "mb" or val == "m":
            return ByteUnit.mB
        if val == "gb" or val == "g":
            return ByteUnit.gB
        return ByteUnit.B

    @staticmethod
    def previous(val):
        """Return the previous value of the unit."""
        if val == ByteUnit.kB:
            return ByteUnit.B
        if val == ByteUnit.mB:
            return ByteUnit.kB
        if val == ByteUnit.gB:
            return ByteUnit.mB
        return ByteUnit.B

    @staticmethod
    def to_int(value: tuple[str, any]) -> int:
        """Convert the value to the bytes unit."""
        if isinstance(value[1], ByteUnit):
            return value[0] * value[1].value

        unit = ByteUnit.get(value[1]).value
        return int(value[0]) * unit

    @staticmethod
    def unit(value: int | float) -> Tuple[float, Any]:
        """Return the next value of the unit.

        This value must be an integer. If we have a decimal part, then we should round it up.
        """
        inter_value = float(value)
        for u in [ByteUnit.B, ByteUnit.kB, ByteUnit.mB, ByteUnit.gB]:
            if inter_value < 1024:
                break
            inter_value /= 1024

        # Now, we calculate the rounding
        if u == ByteUnit.B:
            # We are already in the lowest unit possible, return a rounded value
            return (int(inter_value), u)
        # Check if we have a decimal part, if yes, then we multiply the value by 1024
        dec, _ = math.modf(inter_value)
        if dec != 0.0:
            return (int(inter_value * 1024), ByteUnit.previous(u))
        return (int(inter_value), u)


class JavaByteSize:
    """Java Byte Size tuple representation."""

    def __init__(self, value: str | float | int | None = None, unit: str | ByteUnit | None = None):
        """Constructor of JavaByteSize.

        Args:
            value: the value of the size
            unit: the unit of the size
        """
        if not value and not unit:
            self.value = 0
            self.unit = ByteUnit.B
            return

        u = unit
        if isinstance(unit, str):
            u = ByteUnit.get(unit)
        self.value, self.unit = ByteUnit.unit(float(value) * u.value)

    def percent(self, percentage: float) -> int:
        """Return the percentage of the JavaByteSize."""
        val = ByteUnit.to_int((self.value, self.unit)) * percentage
        return JavaByteSize(val, ByteUnit.B)

    def __eq__(self, other: Any) -> bool:
        """Check if the JavaByteSize is equal to the other value."""
        if not isinstance(other, JavaByteSize):
            raise TypeError("Cannot compare JavaByteSize with other types.")
        return ByteUnit.to_int((self.value, self.unit)) == ByteUnit.to_int(
            (other.value, other.unit)
        )

    def __lt__(self, other: Any) -> bool:
        """Check if the JavaByteSize is less than the other value."""
        if not isinstance(other, JavaByteSize):
            raise TypeError("Cannot compare JavaByteSize with other types.")
        return ByteUnit.to_int((self.value, self.unit)) < ByteUnit.to_int(
            (other.value, other.unit)
        )

    def __gt__(self, other: Any) -> bool:
        """Check if the JavaByteSize is greater than the other value."""
        if not isinstance(other, JavaByteSize):
            raise TypeError("Cannot compare JavaByteSize with other types.")
        return ByteUnit.to_int((self.value, self.unit)) > ByteUnit.to_int(
            (other.value, other.unit)
        )

    def __str__(self) -> str:
        """Return the string representation of the JavaByteSize."""
        return f"{self.value}{str(self.unit.name.lower())[:1]}"


class OpenSearchPerfProfile(Model):
    """Generates an immutable description of the performance profile."""

    class Config:
        """Pydantic config for this model."""

        arbitrary_types_allowed = True

    typ: PerformanceType
    heap_size: JavaByteSize | None = None
    opensearch_yml: Dict[str, str] = {}
    charmed_index_template: Dict[str, str] = {}
    charmed_component_templates: Dict[str, str] = {}

    @classmethod
    def from_str(cls, input_str: str):
        """Create a new instance of this class from a stringified json/dict repr."""
        return cls(typ=input_str)

    @root_validator
    def set_options(cls, values):  # noqa: N805
        """Generate the attributes depending on the input."""
        heap = JavaByteSize(
            OpenSearchPerfProfile.meminfo()["MemTotal"][0],
            OpenSearchPerfProfile.meminfo()["MemTotal"][1],
        )

        val = values["typ"]
        if isinstance(val, str):
            val = PerformanceType(val)

        if val == PerformanceType.PRODUCTION:
            values["heap_size"] = (
                heap.percent(0.25)
                if heap.percent(0.25) > JavaByteSize("1", "g")
                else JavaByteSize("1", "g")
            )

        if val == PerformanceType.STAGING:
            values["heap_size"] = (
                heap.percent(0.1)
                if heap.percent(0.1) > JavaByteSize("1", "g")
                else JavaByteSize("1", "g")
            )

        if val == PerformanceType.TESTING:
            values["heap_size"] = JavaByteSize("1", "gB")

        if val != PerformanceType.TESTING:
            values["opensearch_yml"] = {"indices.memory.index_buffer_size": "25%"}

            values["charmed_index_template"] = {
                "charmed-index-tpl": {
                    "index_patterns": ["*"],
                    "template": {
                        "settings": {
                            "number_of_replicas": "1-all",
                        },
                    },
                },
            }

            values["charmed_component_templates"] = {
                "charmed-default-tpl": {
                    "template": {
                        "settings": {
                            "number_of_replicas": "1-all",
                            "index": {
                                "codec": "zstd_no_dict",
                            },
                        },
                    },
                },
                "charmed-vector-tpl": {
                    "template": {
                        "settings": {
                            "number_of_replicas": "1-all",
                            "index": {
                                "codec": "default",
                            },
                        },
                    },
                },
                "charmed-ingest-tpl": {
                    "template": {
                        "settings": {
                            "number_of_replicas": "1-all",
                            "index": {
                                "codec": "zstd_no_dict",
                                "flush_threshold_size": (
                                    str(values["heap_size"].percent(0.25))
                                    if values["heap_size"].percent(0.25)
                                    > JavaByteSize("512", "mB")
                                    else "512m"
                                ),
                            },
                        },
                    },
                },
            }

        return values

    @staticmethod
    def meminfo() -> dict[str, JavaByteSize]:
        """Read the /proc/meminfo file and return the values."""
        with open("/proc/meminfo") as f:
            meminfo = f.read()
        return {
            line.split()[0][:-1]: (
                int(line.split()[1]),
                ByteUnit.get(line.split()[2] if len(line.split()) > 2 else "b"),
            )
            for line in meminfo.split("\n")
            if line
        }
