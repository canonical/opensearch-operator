# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In-place upgrades on machines

Derived from specification: DA058 - In-Place Upgrades - Kubernetes v2
(https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
"""
import json
import logging
import time
import typing

import ops

import snap
import upgrade
import workload

logger = logging.getLogger(__name__)


class Upgrade(upgrade.Upgrade):
    """In-place upgrades on machines"""

    @property
    def unit_state(self) -> typing.Optional[str]:
        if (
            self._unit_workload_version is not None
            and self._unit_workload_version != self._app_workload_version
        ):
            logger.debug("Unit upgrade state: outdated")
            return "outdated"
        return super().unit_state

    @unit_state.setter
    def unit_state(self, value: str) -> None:
        if value == "healthy":
            # Set snap revision on first install
            self._unit_databag["snap_revision"] = snap.REVISION
            logger.debug(f"Saved {snap.REVISION=} in unit databag while setting state healthy")
        # Super call
        upgrade.Upgrade.unit_state.fset(self, value)

    def _get_unit_healthy_status(
        self, *, workload_status: typing.Optional[ops.StatusBase]
    ) -> ops.StatusBase:
        if self._unit_workload_version == self._app_workload_version:
            if isinstance(workload_status, ops.WaitingStatus):
                return ops.WaitingStatus(
                    f'Router {self._current_versions["workload"]} rev {self._unit_workload_version}'
                )
            return ops.ActiveStatus(
                f'Router {self._current_versions["workload"]} rev {self._unit_workload_version} running'
            )
        if isinstance(workload_status, ops.WaitingStatus):
            return ops.WaitingStatus(
                f'Charmed operator upgraded. Router {self._current_versions["workload"]} rev {self._unit_workload_version}'
            )
        return ops.WaitingStatus(
            f'Charmed operator upgraded. Router {self._current_versions["workload"]} rev {self._unit_workload_version} running'
        )

    @property
    def app_status(self) -> typing.Optional[ops.StatusBase]:
        if not self.is_compatible:
            logger.info(
                "Upgrade incompatible. If you accept potential *data loss* and *downtime*, you can continue by running `force-upgrade` action on each remaining unit"
            )
            return ops.BlockedStatus(
                "Upgrade incompatible. Rollback to previous revision with `juju refresh`"
            )
        return super().app_status

    @property
    def _unit_workload_versions(self) -> typing.Dict[str, str]:
        """{Unit name: installed snap revision}"""
        versions = {}
        for unit in self._sorted_units:
            if version := (self._peer_relation.data[unit].get("snap_revision")):
                versions[unit.name] = version
        return versions

    @property
    def _unit_workload_version(self) -> typing.Optional[str]:
        """Installed snap revision for this unit"""
        return self._unit_databag.get("snap_revision")

    @property
    def _app_workload_version(self) -> str:
        """Snap revision for current charm code"""
        return snap.REVISION

    def reconcile_partition(self, *, action_event: ops.ActionEvent = None) -> None:
        """Handle Juju action to confirm first upgraded unit is healthy and resume upgrade."""
        if action_event:
            self.upgrade_resumed = True
            message = "Upgrade resumed."
            action_event.set_results({"result": message})
            logger.debug(f"Resume upgrade event succeeded: {message}")

    @property
    def upgrade_resumed(self) -> bool:
        """Whether user has resumed upgrade with Juju action

        Reset to `False` after each `juju refresh`
        """
        return json.loads(self._app_databag.get("upgrade-resumed", "false"))

    @upgrade_resumed.setter
    def upgrade_resumed(self, value: bool):
        # Trigger peer relation_changed event even if value does not change
        # (Needed when leader sets value to False during `ops.UpgradeCharmEvent`)
        self._app_databag["-unused-timestamp-upgrade-resume-last-updated"] = str(time.time())

        self._app_databag["upgrade-resumed"] = json.dumps(value)
        logger.debug(f"Set upgrade-resumed to {value=}")

    @property
    def authorized(self) -> bool:
        assert self._unit_workload_version != self._app_workload_version
        for index, unit in enumerate(self._sorted_units):
            if unit.name == self._unit.name:
                # Higher number units have already upgraded
                if index == 1:
                    # User confirmation needed to resume upgrade (i.e. upgrade second unit)
                    logger.debug(f"Second unit authorized to upgrade if {self.upgrade_resumed=}")
                    return self.upgrade_resumed
                return True
            if (
                self._unit_workload_versions.get(unit.name) != self._app_workload_version
                or self._peer_relation.data[unit].get("state") != "healthy"
            ):
                # Waiting for higher number units to upgrade
                return False
        return False

    def upgrade_unit(self, *, workload_: workload.Workload, tls: bool) -> None:
        logger.debug(f"Upgrading {self.authorized=}")
        self.unit_state = "upgrading"
        workload_.upgrade(unit=self._unit, tls=tls)
        self._unit_databag["snap_revision"] = snap.REVISION
        logger.debug(f"Saved {snap.REVISION=} in unit databag after upgrade")
