# Copyright 2023 Canonical Ltd.
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

    def clear(
        self, status_message: str, pattern: CheckPattern = CheckPattern.Equal, app: bool = False
    ):
        """Resets the unit status if it was previously blocked/maintenance with message."""
        context = self.charm.app if app else self.charm.unit

        condition: bool
        match pattern:
            case Status.CheckPattern.Equal:
                condition = context.status.message == status_message
            case Status.CheckPattern.Start:
                condition = context.status.message.startswith(status_message)
            case Status.CheckPattern.End:
                condition = context.status.message.endswith(status_message)
            case Status.CheckPattern.Interpolated:
                condition = (
                    re.fullmatch(status_message.replace("{}", "(?s:.*?)"), status_message)
                    is not None
                )
            case _:
                condition = status_message in context.status.message

        if condition:
            context.status = ActiveStatus()
