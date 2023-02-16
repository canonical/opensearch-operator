# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Cluster-related data structures / model classes."""
import json
from typing import List


class Node:
    """Data class representing a node in a cluster."""

    def __init__(self, name: str, roles: List[str], ip: str):
        self.name = name
        self.roles = list(set(roles))
        self.ip = ip

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

    def __eq__(self, other):
        """Implement equality."""
        if other is None:
            return False

        return (
            self.name == other.name
            and sorted(self.roles) == sorted(other.roles)
            and self.ip == other.ip
        )

    @staticmethod
    def from_dict(input_dict):
        """Create a new instance of this class from a json/dict repr."""
        return Node(input_dict.get("name"), input_dict.get("roles"), input_dict.get("ip"))

    @staticmethod
    def from_str(input_str_dict):
        """Create a new instance of this class from a stringified json/dict repr."""
        return Node.from_dict(json.loads(input_str_dict))
