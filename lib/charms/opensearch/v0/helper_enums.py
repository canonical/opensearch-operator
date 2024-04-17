# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this file we declare the base enum types with string and other types' representations."""
from enum import Enum
from typing import Any

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


class ByteUnit(Enum):
    """As per docs, Java uses the byte format.

    Converts the *B and *iB to the same raw values. kB is the smallest unit.
    """

    kB = 1  # noqa: N815
    mB = 1024  # noqa: N815
    gB = 1024 * 1024  # noqa: N815

    @staticmethod
    def get(name: str) -> int:
        """Convert the value to the required unit."""
        return getattr(ByteUnit, name, None)

    def __str__(self) -> str:
        """String representation of the enum name."""
        return self.name

    def __repr__(self) -> str:
        """String representation of the enum name."""
        return self.name

    def __eq__(self, other: Any) -> bool:
        """Check if the enum name is equal to the other value."""
        if isinstance(other, ByteUnit):
            return self.name == other.name
        if isinstance(other, str):
            return self.name == other
        return False

    @staticmethod
    def to_kb(value: tuple[str, str]) -> int:
        """Convert the value to the KB unit."""
        unit = ByteUnit.get(value[1]).value
        return int(value[0]) * unit

    @staticmethod
    def format(value: tuple[str, str]) -> int:
        """Convert the value to the required unit."""
        val = ByteUnit.to_kb(value)
        unit = ByteUnit.kB
        while val >= 1024:
            val /= 1024
            unit = ByteUnit(unit.value * 1024)

        return val, unit
