from typing import List, Dict

from ops.charm import CharmBase


class Node:

    def __init__(self, name: str, ip_address: str):
        self.name = name
        self.ip_address = ip_address


class ClusterTopology:
    """Class for creating the best possible configuration for a Node.
    Keep in a stored state"""

    def __init__(self, charm: CharmBase):
        self.charm = charm

    def add_node(self):
        pass

    def delete_node(self):
        pass

    def full_conf(self):
        """return a dict describing the configuration of the cluster"""
        # TODO rest api ?

    def ideal_node_conf(self) -> Dict[str, str]:
        pass

    def _recompute_conf(self):
        pass

    def _is_large_cluster(self) -> bool:
        pass

    def _is_resilient(self) -> bool:
        pass


def cluster_manager_eligible_nodes() -> List[Node]:
    """Get list of CM eligible nodes."""


def advised_node_type() -> str:
    """Returns a suggested node type to attempt HA.
    The logic should give the best node type for small or large clusters."""

