# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this file we declare the base enum types with string and other types' representations."""
from enum import Enum

# The unique Charmhub library identifier, never change it
LIBID = "1c7c09021415420b86de372b366dc13f"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class BaseStrEnum(str, Enum):
    """Base Enum class with str representation."""

    def __str__(self):
        """String representation of enum value."""
        return self.value

    @property
    def val(self) -> str:
        """String representation of enum values."""
        return str(self.__str__())
