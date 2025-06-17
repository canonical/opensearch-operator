# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Cluster-related data structures / model classes."""
import json
import logging
from abc import ABC
from datetime import datetime
from hashlib import md5
from typing import Any, Dict, List, Literal, Optional

from charms.opensearch.v0.constants_charm import AZURE_REPO_BASE_PATH, S3_REPO_BASE_PATH
from charms.opensearch.v0.constants_secrets import AZURE_CREDENTIALS, S3_CREDENTIALS
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


MIN_HEAP_SIZE = 1024 * 1024  # 1GB in KB
MAX_HEAP_SIZE = 32 * MIN_HEAP_SIZE  # 32GB in KB


logger = logging.getLogger(__name__)


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
    # We have a breaking change in the model
    # For older charms, this field will not exist and they will be set in the
    # profile called "testing".
    profile: Optional[PerformanceType] = PerformanceType.TESTING
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
    cluster_name_autogenerated: bool = False
    promotion_time: Optional[float]

    @root_validator
    def set_promotion_time(cls, values):  # noqa: N805
        """Set promotion time of a failover to a main CM."""
        if not values["promotion_time"] and values["typ"] == DeploymentType.MAIN_ORCHESTRATOR:
            values["promotion_time"] = datetime.now().timestamp()

        return values


class S3RelDataCredentials(Model):
    """Model class for credentials passed on the PCluster relation."""

    access_key: str = Field(alias="access-key", default=None)
    secret_key: str = Field(alias="secret-key", default=None)

    class Config:
        """Model config of this pydantic model."""

        allow_population_by_field_name = True


class S3RelData(Model):
    """Model class for the S3 relation data.

    This model should receive the data directly from the relation and map it to a model.
    """

    bucket: str = Field(default="")
    endpoint: str = Field(default="")
    region: str = Field(default="")
    base_path: Optional[str] = Field(alias="path", default=S3_REPO_BASE_PATH)
    protocol: Optional[str] = None
    storage_class: Optional[str] = Field(alias="storage-class", default=None)
    tls_ca_chain: Optional[str] = Field(alias="tls-ca-chain", default=None)
    credentials: S3RelDataCredentials = Field(alias=S3_CREDENTIALS, default=S3RelDataCredentials())
    path_style_access: bool = Field(alias="s3-uri-style", default=False)

    class Config:
        """Model config of this pydantic model."""

        allow_population_by_field_name = True

    @root_validator
    def validate_core_fields(cls, values):  # noqa: N805
        """Validate the core fields of the S3 relation data."""
        if (
            not (s3_creds := values.get("credentials"))
            or not s3_creds.access_key
            or not s3_creds.secret_key
        ):
            raise ValueError("Missing fields: access_key, secret_key")

        # NOTE: Both bucket and endpoint must be set. If none of them are set,
        # but credentials were found, this likely means that we are validating for a
        # non cluster_manager application, which only needs credentials.
        if values.get("bucket") and not values.get("endpoint"):
            raise ValueError("Missing field: endpoint")
        if values.get("endpoint") and not values.get("bucket"):
            raise ValueError("Missing field: bucket")
        if not values.get("region"):
            raise ValueError("Missing field: region")

        return values

    @validator("path_style_access", pre=True)
    def change_path_style_type(cls, value) -> bool:  # noqa: N805
        """Coerce a type change of the path_style_access into a bool."""
        if isinstance(value, str):
            return value.lower() == "path"
        return bool(value)

    @validator(S3_CREDENTIALS, check_fields=False)
    def ensure_secret_content(cls, conf: Dict[str, str] | S3RelDataCredentials):  # noqa: N805
        """Ensure the secret content is set."""
        if not conf:
            return None

        data = conf
        if isinstance(conf, dict):
            # We are
            data = S3RelDataCredentials.from_dict(conf)

        for value in data.dict().values():
            if value.startswith("secret://"):
                raise ValueError(f"The secret content must be passed, received {value} instead")
        return data

    @staticmethod
    def get_endpoint_protocol(endpoint: str) -> str:
        """Returns the protocol based on the endpoint."""
        if not endpoint:
            return "https"

        if endpoint.startswith("http://"):
            return "http"
        return "https"

    @classmethod
    def from_relation(cls, input_dict: Optional[Dict[str, Any]]):
        """Create a new instance of this class from a json/dict repr.

        This method creates a nested S3RelDataCredentials object from the input dict.
        """
        if not input_dict:
            return cls()

        creds = S3RelDataCredentials(**input_dict)
        protocol = S3RelData.get_endpoint_protocol(input_dict.get("endpoint"))
        return cls.from_dict(
            dict(input_dict) | {"protocol": protocol, S3_CREDENTIALS: creds.dict()}
        )


class AzureRelDataCredentials(Model):
    """Model class for credentials passed on the Azure relation."""

    storage_account: str = Field(alias="storage-account", default=None)
    secret_key: str = Field(alias="secret-key", default=None)

    class Config:
        """Model config of this pydantic model."""

        allow_population_by_field_name = True


class AzureRelData(Model):
    """Model class for the Azure relation data.

    This model should receive the data directly from the relation and map it to a model.
    """

    storage_account: str = Field(alias="storage-account", default="")
    container: str = Field(default="")
    endpoint: Optional[str] = Field(default="")
    base_path: Optional[str] = Field(alias="path", default=AZURE_REPO_BASE_PATH)
    connection_protocol: Optional[str] = Field(alias="connection-protocol", default=None)
    credentials: AzureRelDataCredentials = Field(
        alias=AZURE_CREDENTIALS, default=AzureRelDataCredentials()
    )

    class Config:
        """Model config of this pydantic model."""

        allow_population_by_field_name = True

    @root_validator
    def validate_core_fields(cls, values):  # noqa: N805
        """Validate the core fields of the azure relation data."""
        if (
            not (creds := values.get("credentials"))
            or not creds.storage_account
            or not creds.secret_key
        ):
            raise ValueError("Missing fields: storage_account, secret_key")

        return values

    @validator(AZURE_CREDENTIALS, check_fields=False)
    def ensure_secret_content(cls, conf: Dict[str, str] | AzureRelDataCredentials):  # noqa: N805
        """Ensure the secret content is set."""
        if not conf:
            return None

        data = conf
        if isinstance(conf, dict):
            data = AzureRelDataCredentials.from_dict(conf)

        for value in data.dict().values():
            if value.startswith("secret://"):
                raise ValueError(f"The secret content must be passed, received {value} instead")
        return data

    @classmethod
    def from_relation(cls, input_dict: Optional[Dict[str, Any]]):
        """Create a new instance of this class from a json/dict repr.

        This method creates a nested AzureRelDataCredentials object from the input dict.
        """
        if not input_dict:
            return cls()

        creds = AzureRelDataCredentials(**input_dict)
        return cls.from_dict(dict(input_dict) | {AZURE_CREDENTIALS: creds.dict()})


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
    azure: Optional[AzureRelDataCredentials]


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
    security_index_initialised: bool = False


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


class OpenSearchPerfProfile(Model):
    """Generates an immutable description of the performance profile."""

    typ: PerformanceType
    heap_size_in_kb: int = MIN_HEAP_SIZE
    opensearch_yml: Dict[str, str] = {}
    charmed_index_template: Dict[str, str] = {}
    charmed_component_templates: Dict[str, str] = {}

    @root_validator
    def set_options(cls, values):  # noqa: N805
        """Generate the attributes depending on the input."""
        # Check if PerformanceType has been rendered correctly
        # if an user creates the OpenSearchPerfProfile
        if "typ" not in values:
            raise AttributeError("Missing 'typ' attribute.")

        if values["typ"] == PerformanceType.TESTING:
            values["heap_size_in_kb"] = MIN_HEAP_SIZE
            return values

        mem_total = OpenSearchPerfProfile.meminfo()["MemTotal"]
        mem_percent = 0.50 if values["typ"] == PerformanceType.PRODUCTION else 0.25

        values["heap_size_in_kb"] = min(int(mem_percent * mem_total), MAX_HEAP_SIZE)

        if values["typ"] != PerformanceType.TESTING:
            values["opensearch_yml"] = {"indices.memory.index_buffer_size": "25%"}

            values["charmed_index_template"] = {
                "charmed-index-tpl": {
                    "index_patterns": ["*"],
                    "template": {
                        "settings": {
                            "number_of_replicas": "1",
                        },
                    },
                },
            }

        return values

    @staticmethod
    def meminfo() -> dict[str, float]:
        """Read the /proc/meminfo file and return the values.

        According to the kernel source code, the values are always in kB:
            https://github.com/torvalds/linux/blob/
                2a130b7e1fcdd83633c4aa70998c314d7c38b476/fs/proc/meminfo.c#L31
        """
        with open("/proc/meminfo") as f:
            meminfo = f.read().split("\n")
            meminfo = [line.split() for line in meminfo if line.strip()]

        return {line[0][:-1]: float(line[1]) for line in meminfo}
