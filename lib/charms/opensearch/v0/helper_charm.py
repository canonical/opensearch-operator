# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility functions for charms related operations."""
import logging
import os
import re
import subprocess
from time import time_ns
from types import SimpleNamespace
from typing import TYPE_CHECKING, List, Union

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.helper_enums import BaseStrEnum
from charms.opensearch.v0.models import App
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import CharmBase
from ops.model import ActiveStatus, StatusBase, Unit

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

# The unique Charmhub library identifier, never change it
LIBID = "293db55a2d8949f8aa5906d04cd541ba"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class Status:
    """Class for managing the various status changes in a charm."""

    class CheckPattern(BaseStrEnum):
        """Enum for types of status comparison."""

        Equal = "equal"
        Start = "start"
        End = "end"
        Contain = "contain"
        Interpolated = "interpolated"

    def __init__(self, charm: "OpenSearchBaseCharm"):
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
            if (
                not app
                and self.charm._upgrade
                and (status := self.charm._upgrade.get_unit_juju_status())
            ):
                context.status = status
            else:
                context.status = ActiveStatus()

    def set(self, status: StatusBase, app: bool = False):
        """Set status on unit or app IF not already set.

        This is seemingly useless, but it is unfortunately needed to avoid updating unnecessarily
        the "last active since" field on the model, which prevents it from stabilizing on small
        machines on integration tests (colliding with "idle period").
        """
        context = self.charm.app if app else self.charm.unit
        # Upgrade app status takes priority over other app statuses
        if app and self.charm._upgrade and (upgrade_status := self.charm._upgrade.app_status):
            context.status = upgrade_status
            return
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


def format_unit_name(unit: Union[Unit, str], app: App) -> str:
    """Format unit_name according the app."""
    if isinstance(unit, Unit):
        unit = unit.name
    return f"{unit.replace('/', '-')}.{app.short_id}"


def all_units(charm: "OpenSearchBaseCharm") -> List[Unit]:
    """Fetch the list of units for the current app."""
    return list(charm.model.get_relation(PeerRelationName).units.union({charm.unit}))


def trigger_peer_rel_changed(
    charm: "OpenSearchBaseCharm",
    only_by_leader: bool = False,
    on_other_units: bool = True,
    on_current_unit: bool = False,
) -> None:
    """Force trigger a peer rel changed event."""
    if only_by_leader and not charm.unit.is_leader():
        return

    if on_other_units or not on_current_unit:
        charm.peers_data.put(Scope.APP if only_by_leader else Scope.UNIT, "update-ts", time_ns())

    if on_current_unit:
        charm.on[PeerRelationName].relation_changed.emit(
            charm.model.get_relation(PeerRelationName)
        )


def run_cmd(command: str, args: str = None) -> SimpleNamespace:
    """Run command.

    Arg:
        command: can contain arguments
        args: command line arguments
    """
    command_with_args = command
    if args is not None:
        command_with_args = f"{command} {args}"

    command_with_args = " ".join(command_with_args.split())

    # only log the command and no arguments to avoid logging sensitive information
    command = command.split()[0]
    logger.debug(f"Executing command: {command}")

    try:
        output = subprocess.run(
            command_with_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
            encoding="utf-8",
            timeout=25,
            env=os.environ,
        )

        if output.returncode != 0:
            logger.error(f"err: {output.stderr} / out: {output.stdout}")
            raise OpenSearchCmdError(cmd=command, out=output.stdout, err=output.stderr)

        return SimpleNamespace(cmd=command, out=output.stdout, err=output.stderr)
    except (TimeoutError, subprocess.TimeoutExpired):
        raise OpenSearchCmdError(cmd=command)
