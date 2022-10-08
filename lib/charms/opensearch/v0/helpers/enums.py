# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this file we declare the base enum types with string and other types' representations."""
from enum import Enum

# The unique Charmhub library identifier, never change it
LIBID = "f4bd9c1dad554f9ea52954b8181cdc19"
LIBAPI = 0
LIBPATCH = 0


class BaseStrEnum(Enum):
    """Base Enum class with str representation."""

    def __str__(self):
        """String representation of enum value."""
        return self.value

    @property
    def val(self) -> str:
        """String representation of enum values."""
        return str(self.__str__())
