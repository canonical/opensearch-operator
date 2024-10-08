# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility classes and methods for getting cluster info, configuration info and suggestions."""
import logging
from typing import TYPE_CHECKING, Dict, List, Optional

from charms.opensearch.v0.constants_charm import GeneratedRoles
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.models import App, Node, PeerClusterApp
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_internal_data import Scope
from tenacity import retry, stop_after_attempt, wait_exponential

# The unique Charmhub library identifier, never change it
LIBID = "80c3b9eff6df437bb4175b1666b73f91"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm


class IndexStateEnum(BaseStrEnum):
    """Enum for index states."""

    OPEN = "open"
    CLOSED = "closed"


class ClusterTopology:
    """Class for creating the best possible configuration for a Node."""

    @staticmethod
    def generated_roles() -> List[str]:
        """Get generated roles for a Node."""
        return GeneratedRoles

    @staticmethod
    def get_cluster_settings(
        opensearch: OpenSearchDistribution,
        host: Optional[str] = None,
        alt_hosts: Optional[List[str]] = None,
        include_defaults: bool = False,
    ) -> Dict[str, any]:
        """Get the cluster settings."""
        settings = opensearch.request(
            "GET",
            f"/_cluster/settings?flat_settings=true&include_defaults={str(include_defaults).lower()}",
            host=host,
            alt_hosts=alt_hosts,
        )

        return dict(settings["defaults"] | settings["persistent"] | settings["transient"])

    @staticmethod
    def recompute_nodes_conf(app_id: str, nodes: List[Node]) -> Dict[str, Node]:
        """Recompute the configuration of all the nodes (cluster set to auto-generate roles)."""
        if not nodes:
            return {}
        logger.debug(f"Roles before re-balancing {({node.name: node.roles for node in nodes})=}")
        nodes_by_name = {}
        current_cluster_nodes = []
        for node in nodes:
            if node.app.id == app_id:
                current_cluster_nodes.append(node)
            else:
                # Leave node unchanged
                nodes_by_name[node.name] = node
        for node in current_cluster_nodes:
            nodes_by_name[node.name] = Node(
                name=node.name,
                # we do this in order to remove any non-default role / add any missing default role
                roles=ClusterTopology.generated_roles(),
                ip=node.ip,
                app=node.app,
                unit_number=node.unit_number,
                temperature=node.temperature,
            )
        logger.debug(
            f"Roles after re-balancing {({name: node.roles for name, node in nodes_by_name.items()})=}"
        )
        return nodes_by_name

    @staticmethod
    def max_cluster_manager_nodes(planned_units) -> int:
        """Get the max number of CM nodes in a cluster."""
        max_managers = planned_units
        if planned_units % 2 == 0:
            max_managers -= 1

        return max_managers

    @staticmethod
    def get_cluster_managers_ips(nodes: List[Node]) -> List[str]:
        """Get the nodes of cluster manager eligible nodes."""
        result = []
        for node in nodes:
            if node.is_cm_eligible():
                result.append(node.ip)

        return result

    @staticmethod
    def get_cluster_managers_names(nodes: List[Node]) -> List[str]:
        """Get the nodes of cluster manager eligible nodes."""
        result = []
        for node in nodes:
            if node.is_cm_eligible():
                result.append(node.name)

        return result

    @staticmethod
    def nodes_count_by_role(nodes: List[Node]) -> Dict[str, int]:
        """Count number of nodes by role."""
        result = {}
        for node in nodes:
            for role in node.roles:
                if role not in result:
                    result[role] = 0
                result[role] += 1

        return result

    @staticmethod
    def nodes_by_role(nodes: List[Node]) -> Dict[str, List[Node]]:
        """Get list of nodes by role."""
        result = {}
        for node in nodes:
            for role in node.roles:
                if role not in result:
                    result[role] = []

                result[role].append(node)

        return result

    @staticmethod
    def data_role_in_cluster_fleet_apps(charm: "OpenSearchBaseCharm") -> bool:
        """Look for data-role through all the roles of all the nodes in all applications"""
        if cluster_apps := charm.peers_data.get_object(Scope.APP, "cluster_fleet_apps"):
            for app in cluster_apps.values():
                p_cluster_app = PeerClusterApp.from_dict(app)
                if "data" in p_cluster_app.roles:
                    return True

        return False

    @staticmethod
    def nodes(
        opensearch: OpenSearchDistribution,
        use_localhost: bool,
        hosts: Optional[List[str]] = None,
    ) -> List[Node]:
        """Get the list of nodes in a cluster."""
        host: Optional[str] = None  # defaults to current unit ip
        alt_hosts: Optional[List[str]] = hosts
        if not use_localhost and hosts:
            host = hosts[0]
            if len(hosts) >= 2:
                alt_hosts = hosts[1:]

        nodes: List[Node] = []
        if use_localhost or host:
            response = opensearch.request(
                "GET", "/_nodes", host=host, alt_hosts=alt_hosts, retries=3
            )
            if "nodes" in response:
                for obj in response["nodes"].values():
                    node = Node(
                        name=obj["name"],
                        roles=obj["roles"],
                        ip=obj["ip"],
                        app=App(id=obj["attributes"]["app_id"]),
                        unit_number=int(obj["name"].split(".")[0].split("-")[-1]),
                        temperature=obj.get("attributes", {}).get("temp"),
                    )
                    nodes.append(node)
        return nodes


class ClusterState:
    """Class for getting cluster state info."""

    @staticmethod
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def shards(
        opensearch: OpenSearchDistribution,
        host: Optional[str] = None,
        alt_hosts: Optional[List[str]] = None,
        verbose: bool = False,
    ) -> List[Dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        cluster_state = opensearch.request(
            "GET", "_cluster/state/routing_table,metadata,nodes", host=host, alt_hosts=alt_hosts
        )

        nodes = cluster_state["nodes"]

        shards_info = []
        for index_name, index_data in cluster_state["routing_table"]["indices"].items():
            for shard_num, shard_data in index_data["shards"].items():
                for shard in shard_data:
                    node_data = nodes.get(shard["node"], {})
                    node_name = node_data.get("name", None)
                    node_ip = (
                        node_data["transport_address"].split(":")[0]
                        if "transport_address" in node_data
                        else None
                    )

                    shard_info = {
                        "index": index_name,
                        "shard": shard_num,
                        "prirep": shard["primary"] and "p" or "r",
                        "state": shard["state"],
                        "ip": node_ip,
                        "node": node_name,
                    }
                    if verbose:
                        shard_info["unassigned.reason"] = shard.get("unassigned_info", {}).get(
                            "reason", None
                        )
                    shards_info.append(shard_info)
        return shards_info

    @staticmethod
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def allocation_explain(
        opensearch: OpenSearchDistribution,
        host: Optional[str] = None,
        alt_hosts: Optional[List[str]] = None,
    ) -> List[Dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        return opensearch.request(
            "GET",
            "/_cluster/allocation/explain?include_disk_info=true&include_yes_decisions=true",
            host=host,
            alt_hosts=alt_hosts,
        )

    @staticmethod
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def indices(
        opensearch: OpenSearchDistribution,
        host: Optional[str] = None,
        alt_hosts: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        # Get cluster state
        cluster_state = opensearch.request(
            "GET", "/_cluster/state/metadata", host=host, alt_hosts=alt_hosts
        )
        indices_state = cluster_state["metadata"]["indices"]

        # Get cluster health
        cluster_health = opensearch.request(
            "GET", "/_cluster/health?level=indices", host=host, alt_hosts=alt_hosts
        )
        indices_health = cluster_health["indices"]

        idx = {}
        for index in indices_state.keys():
            idx[index] = {
                "health": indices_health[index]["status"],
                "status": indices_state[index]["state"],
            }
        return idx

    @staticmethod
    def shards_by_state(
        opensearch: OpenSearchDistribution,
        host: Optional[str] = None,
        alt_hosts: Optional[List[str]] = None,
    ) -> Dict[str, List[str]]:
        """Get the shards count by state."""
        shards = ClusterState.shards(opensearch, host=host, alt_hosts=alt_hosts)

        shards_state_map = {}
        for shard in shards:
            state = shard.get("state")

            shards_state_map[state] = shards_state_map.get(state, 0) + 1

        return shards_state_map

    @staticmethod
    def busy_shards_by_unit(
        opensearch: OpenSearchDistribution,
        host: Optional[str] = None,
        alt_hosts: Optional[List[str]] = None,
    ) -> Dict[str, List[str]]:
        """Get the busy shards of each index in the cluster."""
        shards = ClusterState.shards(opensearch, host=host, alt_hosts=alt_hosts)

        busy_shards = {}
        for shard in shards:
            state = shard.get("state")
            if state not in ["INITIALIZING", "RELOCATING"]:
                continue

            unit_name = shard["node"]
            if unit_name not in busy_shards:
                busy_shards[unit_name] = []

            busy_shards[unit_name].append(shard["index"])

        return busy_shards

    @staticmethod
    def health(
        opensearch: OpenSearchDistribution,
        wait_for_green: bool,
        host: Optional[str] = None,
        alt_hosts: Optional[List[str]] = None,
    ) -> Dict[str, any]:
        """Fetch the cluster health."""
        endpoint = "/_cluster/health"

        # Extra logging: list shards and index status
        logger.debug(
            "indices status:\n"
            f"{opensearch.request('GET', '/_cat/indices?v')}\n"
            "indices shards:\n"
            f"{opensearch.request('GET', '/_cat/shards?v')}\n"
        )

        timeout = 5
        if wait_for_green:
            endpoint = f"{endpoint}?wait_for_status=green&timeout=1m"
            timeout = 75

        return opensearch.request(
            "GET",
            endpoint,
            host=host,
            alt_hosts=alt_hosts,
            timeout=timeout,
        )
