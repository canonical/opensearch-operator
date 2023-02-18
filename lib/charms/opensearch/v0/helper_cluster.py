# Copyright 2022 Canonical Ltd.
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

        For now, we don't allow to end-user control roles.
        The logic here is:
            — Half of the nodes should be CM-eligible.
            — All others should not participate in the voting to speedup voting time.
        """
        nodes_by_roles = ClusterTopology.nodes_count_by_role(nodes)

        max_cms, max_voters = ClusterTopology.max_cm_and_voter_nodes(planned_units)

        base_roles = ["data", "ingest", "ml", "coordinating_only"]

        if (
            nodes_by_roles.get("cluster_manager", 0) + nodes_by_roles.get("voting_only", 0)
            >= max_voters
        ):
            return base_roles

        if nodes_by_roles.get("cluster_manager", 0) >= max_cms:
            return base_roles + ["voting_only"]

        return base_roles + ["cluster_manager"]

    @staticmethod
    def node_with_new_roles(remaining_nodes: List[Node]) -> Optional[Node]:
        """Pick and recompute the roles of the best node to re-balance the cluster."""
        max_cms, max_voters = ClusterTopology.max_cm_and_voter_nodes(len(remaining_nodes))
        max_voting_only = max_voters - max_cms

        nodes_by_roles = ClusterTopology.nodes_count_by_role(remaining_nodes)
        current_cms = nodes_by_roles.get("cluster_manager", 0)
        current_voting_only = nodes_by_roles.get("voting_only", 0)

        # the nodes involved in the voting are intact, do nothing
        if current_cms + current_voting_only == max_voters:
            logger.debug("Suggesting NO changes to the nodes.")
            return None

        nodes_by_roles = ClusterTopology.nodes_by_role(remaining_nodes)

        if current_cms > max_cms:
            # remove cm from a node
            cm = choice(nodes_by_roles["cluster_manager"])
            logger.debug(f"Suggesting - removal of 'CM': {cm.name}")
            return Node(cm.name, [r for r in cm.roles if r != "cluster_manager"], cm.ip)

        if current_voting_only > max_voting_only:
            # remove voting_only from a node
            voting_only = choice(nodes_by_roles["voting_only"])
            logger.debug(f"Suggesting - removal of 'voting_only': {voting_only.name}")
            return Node(
                voting_only.name,
                [r for r in voting_only.roles if r != "voting_only"],
                voting_only.ip,
            )

        exclude_roles = {"cluster_manager", "voting_only"}
        data = choice(
            [node for node in nodes_by_roles["data"] if not exclude_roles & (set(node.roles))]
        )

        if current_cms < max_cms:
            # add cm to a data node (that doesn't have voting_only)
            logger.debug(f"Suggesting - Addition of 'CM' to data: {data.name}")
            return Node(data.name, data.roles + ["cluster_manager"], data.ip)

        # add voting_only to a data node
        logger.debug(f"Suggesting - Addition of 'voting_only' to data: {data.name}")
        return Node(data.name, data.roles + ["voting_only"], data.ip)

    @staticmethod
    def max_cm_and_voter_nodes(planned_units) -> (int, int):
        """Get the max number of CMs and voters on a cluster."""
        max_managers = planned_units
        max_voters = planned_units
        if planned_units % 2 == 0:
            max_managers -= 1
            max_voters -= 1

        if max_managers > 3:
            # for a cluster of +3 nodes, we want to have half of the nodes as CMs
            max_managers = max_managers // 2 + 1

        return max_managers, max_voters

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
                    nodes.append(Node(obj["name"], obj["roles"], obj["ip"]))

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
        opensearch: OpenSearchDistribution, host: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Get all shards of all indexes in the cluster."""
        return opensearch.request("GET", "/_cat/shards", host=host)

    @staticmethod
    def busy_shards_by_unit(
        opensearch: OpenSearchDistribution, host: Optional[str] = None
    ) -> Dict[str, List[str]]:
        """Get the busy shards of each index in the cluster."""
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

    @staticmethod
    def health(
        opensearch: OpenSearchDistribution,
        wait_for_green: bool,
        host: Optional[str] = None,
        alt_hosts: Optional[List[str]] = None,
    ) -> Dict[str, any]:
        """Fetch the cluster health."""
        endpoint = "/_cluster/health"
        if wait_for_green:
            endpoint = f"{endpoint}?wait_for_status=green&timeout=1m"

        return opensearch.request(
            "GET",
            endpoint,
            host=host,
            alt_hosts=alt_hosts,
        )
