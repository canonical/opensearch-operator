# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility classes and methods for getting cluster info, configuration info and suggestions."""
import logging
from typing import Dict, List, Optional

from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.models import Node
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from tenacity import retry, stop_after_attempt, wait_exponential

# The unique Charmhub library identifier, never change it
LIBID = "80c3b9eff6df437bb4175b1666b73f91"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class IndexStateEnum(BaseStrEnum):
    """Enum for index states."""

    OPEN = "open"
    CLOSED = "closed"


class ClusterTopology:
    """Class for creating the best possible configuration for a Node."""

    @staticmethod
    def suggest_roles(nodes: List[Node], planned_units: int) -> List[str]:
        """Get roles for a Node.

        This method should be read in the context of a "rolling" start -
        only 1 unit at a time will call this.

        For now, we don't allow to end-user control roles.
        The logic here is, if number of planned units is:
            — odd: "all" the nodes are cm_eligible nodes.
            — even: "all - 1" are cm_eligible and 1 data node.
        """
        # TODO: remove in https://github.com/canonical/opensearch-operator/issues/230
        return ["data", "ingest", "ml", "coordinating_only", "cluster_manager"]

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
    def recompute_nodes_conf(app_name: str, nodes: List[Node]) -> Dict[str, Node]:
        # TODO: remove in https://github.com/canonical/opensearch-operator/issues/230
        """Recompute the configuration of all the nodes (cluster set to auto-generate roles)."""
        if not nodes:
            return {}
        logger.debug(f"Roles before re-balancing {({node.name: node.roles for node in nodes})=}")
        nodes_by_name = {}
        current_cluster_nodes = []
        for node in nodes:
            if node.app_name == app_name:
                current_cluster_nodes.append(node)
            else:
                # Leave node unchanged
                nodes_by_name[node.name] = node
        for node in current_cluster_nodes:
            nodes_by_name[node.name] = Node(
                name=node.name,
                # we do this in order to remove any non-default role / add any missing default role
                roles=["data", "ingest", "ml", "coordinating_only", "cluster_manager"],
                ip=node.ip,
                app_name=node.app_name,
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
    def nodes(
        opensearch: OpenSearchDistribution,
        use_localhost: bool,
        hosts: Optional[List[str]] = None,
        only_this_juju_app: str = None,
    ) -> List[Node]:
        """Get the list of nodes in a cluster.

        If only_this_juju_app, only return nodes that are
        part of the provided Juju application within the cluster.

        For small deployments, behavior is the same independent of
        the value of only_this_juju_app. But for large deployments,
        it will toggle between grabbing all the nodes or just the nodes
        that belong to the same juju application.        
        """
        host: Optional[str] = None  # defaults to current unit ip
        alt_hosts: Optional[List[str]] = hosts
        if not use_localhost and hosts:
            host, alt_hosts = hosts[0], hosts[1:]

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
                        app_name="-".join(obj["name"].split("-")[:-1]),
                        unit_number=int(obj["name"].split("-")[-1]),
                        temperature=obj.get("attributes", {}).get("temp"),
                    )
                    if "-".join(obj["name"].split("-")[:-1]) == only_this_juju_app:
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
    ) -> List[Dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        return opensearch.request("GET", "/_cat/shards", host=host, alt_hosts=alt_hosts)

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
    ) -> List[Dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        endpoint = "/_cat/indices?expand_wildcards=all"
        idx = {}
        for index in opensearch.request("GET", endpoint, host=host, alt_hosts=alt_hosts):
            idx[index["index"]] = {"health": index["health"], "status": index["status"]}
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
