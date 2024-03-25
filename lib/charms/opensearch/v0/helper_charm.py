# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility functions for charms related operations."""
import re
from datetime import datetime

from charms.data_platform_libs.v0.data_interfaces import Scope
from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.helper_enums import BaseStrEnum
from ops import CharmBase
from ops.model import ActiveStatus, StatusBase

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
        if pattern == Status.CheckPattern.Equal:
            condition = context.status.message == status_message
        elif pattern == Status.CheckPattern.Start:
            condition = context.status.message.startswith(status_message)
        elif pattern == Status.CheckPattern.End:
            condition = context.status.message.endswith(status_message)
        elif pattern == Status.CheckPattern.Interpolated:
            condition = (
                re.fullmatch(status_message.replace("{}", "(?s:.*?)"), status_message) is not None
            )
        else:
            condition = status_message in context.status.message

        if condition:
            context.status = ActiveStatus()

    def set(self, status: StatusBase, app: bool = False):
        """Set status on unit or app IF not already set.

        This is seemingly useless, but it is unfortunately needed to avoid updating unnecessarily
        the "last active since" field on the model, which prevents it from stabilizing on small
        machines on integration tests (colliding with "idle period").
        """
        context = self.charm.app if app else self.charm.unit
        if context.status == status:
            return

        context.status = status


class RelDepartureReason(BaseStrEnum):
    """Enum depicting the 3 various causes of a Relation Departed event."""

    APP_REMOVAL = "app-removal"
    SCALE_DOWN = "scale-down"
    REL_BROKEN = "rel-broken"


def relation_departure_reason(charm: CharmBase, relation_name: str) -> RelDepartureReason:
    """Compute the reason behind a relation departed event."""
    # fetch relation info
    goal_state = charm.model._backend._run("goal-state", return_output=True, use_json=True)
    rel_info = goal_state["relations"][relation_name]

    # check dying units
    dying_units = [
        unit_data["status"] == "dying"
        for unit, unit_data in rel_info.items()
        if unit != relation_name
    ]

    # check if app removal
    if all(dying_units):
        return RelDepartureReason.APP_REMOVAL

    if any(dying_units):
        return RelDepartureReason.SCALE_DOWN

    return RelDepartureReason.REL_BROKEN


def trigger_leader_peer_rel_changed(charm: CharmBase) -> None:
    """Force trigger a peer rel changed event by leader."""
    if not charm.unit.is_leader():
        return

    charm.peers_data.put(Scope.APP, "triggered", datetime.now().timestamp())
    charm.on[PeerRelationName].relation_changed.emit(charm.model.get_relation(PeerRelationName))
