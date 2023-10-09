# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility classes and methods for getting cluster info, configuration info and suggestions."""
import logging
from random import choice
from typing import Dict, List, Optional

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
        max_cms = ClusterTopology.max_cluster_manager_nodes(planned_units)

        base_roles = ["data", "ingest", "ml", "coordinating_only"]

        nodes_by_roles = ClusterTopology.nodes_count_by_role(nodes)
        if nodes_by_roles.get("cluster_manager", 0) == max_cms:
            return base_roles

        return base_roles + ["cluster_manager"]

    @staticmethod
    def recompute_nodes_conf(nodes: List[Node]) -> Dict[str, Node]:
        """Recompute the configuration of all the nodes."""
        nodes_by_name = dict([(node.name, node) for node in nodes])

        updated_node = ClusterTopology.node_with_new_roles(nodes)
        if updated_node:
            nodes_by_name[updated_node.name] = updated_node

        # this is in case the nodes had had a change in the "base roles", i.e: removed "ingest"
        base_roles = ["data", "ingest", "ml", "coordinating_only"]
        for name, node in nodes_by_name.items():
            node.roles = list(set(node.roles + base_roles))

        return nodes_by_name

    @staticmethod
    def node_with_new_roles(remaining_nodes: List[Node]) -> Optional[Node]:
        """Pick and recompute the roles of the best node to re-balance the cluster."""
        max_cms = ClusterTopology.max_cluster_manager_nodes(len(remaining_nodes))

        nodes_by_roles = ClusterTopology.nodes_by_role(remaining_nodes)
        nodes_count_by_roles = ClusterTopology.nodes_count_by_role(remaining_nodes)
        current_cms = nodes_count_by_roles.get("cluster_manager", 0)

        # the nodes involved in the voting are intact, do nothing
        if current_cms == max_cms:
            logger.debug("Suggesting NO changes to the nodes.")
            return None

        if current_cms > max_cms:
            # remove cm from a node
            cm = choice(nodes_by_roles["cluster_manager"])
            logger.debug(f"Suggesting - removal of 'CM': {cm.name}")
            return Node(
                name=cm.name, roles=[r for r in cm.roles if r != "cluster_manager"], ip=cm.ip
            )

        # when cm count smaller than expected
        data_only_nodes = [
            node for node in nodes_by_roles["data"] if "cluster_manager" not in node.roles
        ]

        # no data-only node available to change, leave
        if not data_only_nodes:
            logger.debug("Suggesting NO changes to the nodes.")
            return None

        # add cm to a data only (non cm) node
        data = choice(data_only_nodes)
        logger.debug(f"Suggesting - Addition of 'CM' to data: {data.name}")
        return Node(name=data.name, roles=data.roles + ["cluster_manager"], ip=data.ip)

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
    ) -> List[Node]:
        """Get the list of nodes in a cluster."""
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
    ) -> List[Dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        return opensearch.request("GET", "/_cat/shards", host=host, alt_hosts=alt_hosts)

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
