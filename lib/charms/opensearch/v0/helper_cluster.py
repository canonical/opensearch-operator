# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility class for getting cluster info, configuration info and suggestions."""

from typing import Dict, List

from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from tenacity import retry, stop_after_attempt, wait_exponential

# The unique Charmhub library identifier, never change it
LIBID = "80c3b9eff6df437bb4175b1666b73f91"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class Node:
    """Data class representing a node in a cluster."""

    def __init__(self, name: str, roles: List[str], ip: str):
        self.name = name
        self.roles = set(roles)
        self.ip = ip


class ClusterTopology:
    """Class for creating the best possible configuration for a Node.

    The current logic is to try to get to the config:
        - 2 dedicated cluster manager nodes
        - 1 voting only data node
    And create them with the following order:
        - cm0
        - data, voting only
        - cm1
        - data
        - data
    """

    @staticmethod
    def suggest_roles(nodes: List[Node]) -> List[str]:
        """Get roles for a Node, for now, we only focus on the 3 most important roles.

        We will do more interesting things with the nodes list, to find the best role.
        The logic here is:
            - the first node should be a CM-eligible node, but will add "data" to it
            - the second node should be a data and voting-only node, so that:
                - a 2 nodes cluster can function
                - when a 2CM-eligible node joins, the CM voting can happen immediately
            - the 3rd one should be a CM-eligible, but will add "data" to it
            - the +4 nodes should be data etc.
        """
        nodes_by_roles = ClusterTopology.nodes_count_by_role(nodes)
        if nodes_by_roles.get("cluster_manager", 0) == 0:
            return ["cluster_manager", "data"]

        if nodes_by_roles.get("voting_only", 0) == 0:
            return ["voting_only", "data"]

        if nodes_by_roles["cluster_manager"] == 1:
            return ["cluster_manager", "data"]

        return ["data"]

    @staticmethod
    def remaining_nodes_for_bootstrap(nodes: List[Node]) -> int:
        """Check if cluster is bootstrapped. 2 cm + 1 voting only nodes created."""
        nodes_count = ClusterTopology.nodes_count_by_role(nodes)

        cms = 2 - nodes_count.get("cluster_manager", 0)
        voting_only = 1 - nodes_count.get("voting_only", 0)

        return cms + voting_only

    @staticmethod
    def get_cluster_managers_ips(nodes: List[Node]) -> List[str]:
        """Get the nodes of cluster manager eligible nodes."""
        result = []
        for node in nodes:
            if "cluster_manager" in node.roles:
                result.append(node.ip)

        return result

    @staticmethod
    def get_cluster_managers_names(nodes: List[Node]) -> List[str]:
        """Get the nodes of cluster manager eligible nodes."""
        result = []
        for node in nodes:
            if "cluster_manager" in node.roles:
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


class ClusterState:
    """Class for getting cluster state info."""

    @staticmethod
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def shards(opensearch: OpenSearchDistribution, host: str = None) -> List[Dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        return opensearch.request("GET", "/_cat/shards", host=host)

    @staticmethod
    def busy_shards_by_unit(
        opensearch: OpenSearchDistribution, host: str = None
    ) -> Dict[str, List[str]]:
        """Get the busy shards of the indexes of the cluster."""
        shards = ClusterState.shards(opensearch, host)

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
