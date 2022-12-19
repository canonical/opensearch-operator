# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility functions for charms related operations."""
import re

from charms.opensearch.v0.helper_enums import BaseStrEnum
from ops.model import ActiveStatus

# The unique Charmhub library identifier, never change it
LIBID = "293db55a2d8949f8aa5906d04cd541ba"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class Status:
    """Class for managing the various status changes in a charm."""

    class CheckPattern(BaseStrEnum):
        """Enum for types of status comparison."""

        Equal = "equal"
        Start = "start"
        End = "end"
        Contain = "contain"
        Interpolated = "interpolated"

    def __init__(self, charm):
        self.charm = charm

    def clear(self, status_message: str, pattern: CheckPattern = CheckPattern.Equal):
        """Resets the unit status if it was previously blocked/maintenance with message."""
        unit = self.charm.unit

        condition: bool
        if pattern == Status.CheckPattern.Equal:
            condition = unit.status.message == status_message
        elif pattern == Status.CheckPattern.Start:
            condition = unit.status.message.startswith(status_message)
        elif pattern == Status.CheckPattern.End:
            condition = unit.status.message.endswith(status_message)
        elif pattern == Status.CheckPattern.Interpolated:
            condition = (
                re.fullmatch(status_message.replace("{}", "(?s:.*?)"), status_message) is not None
            )
        else:
            condition = status_message in unit.status.message

        if condition:
            unit.status = ActiveStatus()
