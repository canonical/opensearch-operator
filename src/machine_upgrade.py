# Copyright 2024 Canonical Ltd.
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

import upgrade
from opensearch import SNAP_REVISION, OpenSearchSnap

logger = logging.getLogger(__name__)

FORCE_ACTION_NAME = "force-upgrade"


class Upgrade(upgrade.Upgrade):
    """In-place upgrades on machines"""

    @property
    def unit_state(self) -> typing.Optional[upgrade.UnitState]:
        """Unit upgrade state"""
        if (
            self._unit_workload_container_version is not None
            and self._unit_workload_container_version != self._app_workload_container_version
        ):
            logger.debug("Unit upgrade state: outdated")
            return upgrade.UnitState.OUTDATED
        return super().unit_state

    @unit_state.setter
    def unit_state(self, value: upgrade.UnitState) -> None:
        # Super call
        upgrade.Upgrade.unit_state.fset(self, value)

    def _get_unit_healthy_status(self) -> ops.StatusBase:
        if self._unit_workload_container_version == self._app_workload_container_version:
            return ops.ActiveStatus(
                f'OpenSearch {self._unit_workload_version} running; Snap rev {self._unit_workload_container_version}; Charmed operator {self._current_versions["charm"]}'
            )
        return ops.ActiveStatus(
            f'OpenSearch {self._unit_workload_version} running; Snap rev {self._unit_workload_container_version} (outdated); Charmed operator {self._current_versions["charm"]}'
        )

    @property
    def app_status(self) -> typing.Optional[ops.StatusBase]:
        """App upgrade status"""
        if not self.in_progress:
            return
        if not self.is_compatible:
            logger.info(
                "Upgrade incompatible. If you accept potential *data loss* and *downtime*, you can continue by running `force-upgrade` action on each remaining unit"
            )
            return ops.BlockedStatus(
                "Upgrade incompatible. Rollback to previous revision with `juju refresh`"
            )
        return super().app_status

    @property
    def _unit_workload_container_versions(self) -> typing.Dict[str, str]:
        """{Unit name: installed snap revision}"""
        versions = {}
        for unit in self._sorted_units:
            if version := (self._peer_relation.data[unit].get("snap_revision")):
                versions[unit.name] = version
        return versions

    @property
    def _unit_workload_container_version(self) -> typing.Optional[str]:
        """Installed snap revision for this unit"""
        return self._unit_databag.get("snap_revision")

    @_unit_workload_container_version.setter
    def _unit_workload_container_version(self, value: str):
        self._unit_databag["snap_revision"] = value

    @property
    def _app_workload_container_version(self) -> str:
        """Snap revision for current charm code"""
        return SNAP_REVISION

    @property
    def _unit_workload_version(self) -> typing.Optional[str]:
        """Installed OpenSearch version for this unit"""
        return self._unit_databag.get("workload_version")

    @_unit_workload_version.setter
    def _unit_workload_version(self, value: str):
        self._unit_databag["workload_version"] = value

    def reconcile_partition(self, *, action_event: ops.ActionEvent = None) -> None:
        """Handle Juju action to confirm first upgraded unit is healthy and resume upgrade."""
        if action_event:
            unit = self._sorted_units[0]  # First unit to upgrade
            state = self._peer_relation.data[unit].get("state")
            if state:
                state = upgrade.UnitState(state)
            outdated = (
                self._unit_workload_container_versions.get(unit.name)
                != self._app_workload_container_version
            )
            unhealthy = state is not upgrade.UnitState.HEALTHY
            if outdated or unhealthy:
                if outdated:
                    message = "Highest number unit has not upgraded yet. Upgrade will not resume."
                else:
                    message = "Highest number unit is unhealthy. Upgrade will not resume."
                logger.debug(f"Resume upgrade event failed: {message}")
                action_event.fail(message)
                return
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
        """Whether this unit is authorized to upgrade

        Only applies to machine charm

        Raises:
            PrecheckFailed: App is not ready to upgrade
        """
        assert self._unit_workload_container_version != self._app_workload_container_version
        assert self.versions_set
        for index, unit in enumerate(self._sorted_units):
            if unit.name == self._unit.name:
                # Higher number units have already upgraded
                if index == 0:
                    if (
                        json.loads(self._app_databag["versions"])["charm"]
                        == self._current_versions["charm"]
                    ):
                        # Assumes charm version uniquely identifies charm revision
                        logger.debug("Rollback detected. Skipping pre-upgrade check")
                    else:
                        # Run pre-upgrade check
                        # (in case user forgot to run pre-upgrade-check action)
                        self.pre_upgrade_check()
                        logger.debug("Pre-upgrade check after `juju refresh` successful")
                elif index == 1:
                    # User confirmation needed to resume upgrade (i.e. upgrade second unit)
                    logger.debug(f"Second unit authorized to upgrade if {self.upgrade_resumed=}")
                    return self.upgrade_resumed
                return True
            state = self._peer_relation.data[unit].get("state")
            if state:
                state = upgrade.UnitState(state)
            if (
                self._unit_workload_container_versions.get(unit.name)
                != self._app_workload_container_version
                or state is not upgrade.UnitState.HEALTHY
            ):
                # Waiting for higher number units to upgrade
                logger.debug(f"Upgrade not authorized. Waiting for {unit.name=} to upgrade")
                return False
        logger.debug(f"Upgrade not authorized. Waiting for {unit.name=} to upgrade")
        return False

    def upgrade_unit(self, *, snap: OpenSearchSnap) -> None:
        """Upgrade this unit.

        Only applies to machine charm
        """
        logger.debug("Upgrading unit")
        self.unit_state = upgrade.UnitState.UPGRADING
        snap.install()
        self._unit_workload_container_version = SNAP_REVISION
        self._unit_workload_version = self._current_versions["workload"]
        logger.debug(
            f'Saved {SNAP_REVISION=} and {self._current_versions["workload"]=} in unit databag after upgrade'
        )

    def save_snap_revision_after_first_install(self):
        """Set snap revision on first install"""
        self._unit_workload_container_version = SNAP_REVISION
        self._unit_workload_version = self._current_versions["workload"]
        logger.debug(
            f'Saved {SNAP_REVISION=} and {self._current_versions["workload"]=} in unit databag after first install'
        )
