# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Cluster-related data structures / model classes."""
import json
from abc import ABC
from enum import Enum
from typing import Any, Dict, List

# The unique Charmhub library identifier, never change it
LIBID = "6007e8030e4542e6b189e2873c8fbfef"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class Model(ABC):
    """Base model class."""

    def to_str(self) -> str:
        """Deserialize object into a string."""
        return json.dumps(
            vars(self), default=lambda x: x.value if isinstance(x, Enum) else vars(x)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Deserialize object into a dict."""
        return json.loads(self.to_str())

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
