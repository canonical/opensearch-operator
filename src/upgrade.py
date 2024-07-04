# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In-place upgrades

Based off specification: DA058 - In-Place Upgrades - Kubernetes v2
(https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
"""

import abc
import copy
import enum
import json
import logging
import pathlib
import typing

import ops
import poetry.core.constraints.version as poetry_version
from charms.opensearch.v0.helper_cluster import ClusterTopology
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_health import HealthColors

import status_exception

logger = logging.getLogger(__name__)


PEER_RELATION_ENDPOINT_NAME = "upgrade-version-a"
PRECHECK_ACTION_NAME = "pre-upgrade-check"
RESUME_ACTION_NAME = "resume-upgrade"


def unit_number(unit_: ops.Unit) -> int:
    """Get unit number"""
    return int(unit_.name.split("/")[-1])


class PeerRelationNotReady(Exception):
    """Upgrade peer relation not available (to this unit)"""


class PrecheckFailed(status_exception.StatusException):
    """App is not ready to upgrade"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(
            ops.BlockedStatus(
                f"Rollback with `juju refresh`. Pre-upgrade check failed: {self.message}"
            )
        )


class UnitState(str, enum.Enum):
    """Unit upgrade state"""

    HEALTHY = "healthy"
    RESTARTING = "restarting"  # Kubernetes only
    UPGRADING = "upgrading"  # Machines only
    OUTDATED = "outdated"  # Machines only


class Upgrade(abc.ABC):
    """In-place upgrades"""

    def __init__(self, charm_: ops.CharmBase) -> None:
        relations = charm_.model.relations[PEER_RELATION_ENDPOINT_NAME]
        if not relations:
            raise PeerRelationNotReady
        assert len(relations) == 1
        self._charm = charm_
        self._peer_relation = relations[0]
        self._unit: ops.Unit = charm_.unit
        self._unit_databag = self._peer_relation.data[self._unit]
        self._app_databag = self._peer_relation.data[charm_.app]
        self._app_name = charm_.app.name
        self._current_versions = {}  # For this unit
        for version, file_name in {
            "charm": "charm_version",
            "workload": "workload_version",
        }.items():
            self._current_versions[version] = pathlib.Path(file_name).read_text().strip()

    @property
    def unit_state(self) -> typing.Optional[UnitState]:
        """Unit upgrade state"""
        if state := self._unit_databag.get("state"):
            return UnitState(state)

    @unit_state.setter
    def unit_state(self, value: UnitState) -> None:
        self._unit_databag["state"] = value.value

    @property
    def is_compatible(self) -> bool:
        """Whether upgrade is supported from previous versions"""
        assert self.versions_set
        previous_version_strs: typing.Dict[str, str] = json.loads(self._app_databag["versions"])
        # TODO charm versioning: remove `.split("+")` (which removes git hash before comparing)
        previous_version_strs["charm"] = previous_version_strs["charm"].split("+")[0]
        previous_versions: typing.Dict[str, poetry_version.Version] = {
            key: poetry_version.Version.parse(value)
            for key, value in previous_version_strs.items()
        }
        current_version_strs = copy.copy(self._current_versions)
        current_version_strs["charm"] = current_version_strs["charm"].split("+")[0]
        current_versions = {
            key: poetry_version.Version.parse(value) for key, value in current_version_strs.items()
        }
        try:
            if (
                previous_versions["charm"] > current_versions["charm"]
                or previous_versions["charm"].major != current_versions["charm"].major
            ):
                logger.debug(
                    f'{previous_versions["charm"]=} incompatible with {current_versions["charm"]=}'
                )
                return False
            if (
                previous_versions["workload"] > current_versions["workload"]
                or previous_versions["workload"].major != current_versions["workload"].major
            ):
                logger.debug(
                    f'{previous_versions["workload"]=} incompatible with {current_versions["workload"]=}'
                )
                return False
            logger.debug(
                f"Versions before upgrade compatible with versions after upgrade {previous_version_strs=} {self._current_versions=}"
            )
            return True
        except KeyError as exception:
            logger.debug(f"Version missing from {previous_versions=}", exc_info=exception)
            return False

    @property
    def in_progress(self) -> bool:
        """Whether upgrade is in progress"""
        logger.debug(
            f"{self._app_workload_container_version=} {self._unit_workload_container_versions=}"
        )
        return any(
            version != self._app_workload_container_version
            for version in self._unit_workload_container_versions.values()
        )

    @property
    def _sorted_units(self) -> typing.List[ops.Unit]:
        """Units sorted from highest to lowest unit number"""
        return sorted((self._unit, *self._peer_relation.units), key=unit_number, reverse=True)

    @abc.abstractmethod
    def _get_unit_healthy_status(self) -> ops.StatusBase:
        """Status shown during upgrade if unit is healthy"""

    def get_unit_juju_status(self) -> typing.Optional[ops.StatusBase]:
        """Unit upgrade status"""
        if self.in_progress:
            return self._get_unit_healthy_status()

    @property
    def app_status(self) -> typing.Optional[ops.StatusBase]:
        """App upgrade status"""
        if not self.in_progress:
            return
        if not self.upgrade_resumed:
            # User confirmation needed to resume upgrade (i.e. upgrade second unit)
            # Statuses over 120 characters are truncated in `juju status` as of juju 3.1.6 and
            # 2.9.45
            return ops.BlockedStatus(
                f"Upgrading. Verify highest unit is healthy & run `{RESUME_ACTION_NAME}` action. To rollback, `juju refresh` to last revision"
            )
        return ops.MaintenanceStatus(
            "Upgrading. To rollback, `juju refresh` to the previous revision"
        )

    @property
    def versions_set(self) -> bool:
        """Whether versions have been saved in app databag

        Should only be `False` during first charm install

        If a user upgrades from a charm that does not set versions, this charm will get stuck.
        """
        return self._app_databag.get("versions") is not None

    def set_versions_in_app_databag(self) -> None:
        """Save current versions in app databag

        Used after next upgrade to check compatibility (i.e. whether that upgrade should be
        allowed)
        """
        assert not self.in_progress
        logger.debug(f"Setting {self._current_versions=} in upgrade peer relation app databag")
        self._app_databag["versions"] = json.dumps(self._current_versions)
        logger.debug(f"Set {self._current_versions=} in upgrade peer relation app databag")

    @property
    @abc.abstractmethod
    def upgrade_resumed(self) -> bool:
        """Whether user has resumed upgrade with Juju action"""

    @property
    @abc.abstractmethod
    def _unit_workload_container_versions(self) -> typing.Dict[str, str]:
        """{Unit name: unique identifier for unit's workload container version}

        If and only if this version changes, the workload will restart (during upgrade or
        rollback).

        On Kubernetes, the workload & charm are upgraded together
        On machines, the charm is upgraded before the workload

        This identifier should be comparable to `_app_workload_container_version` to determine if
        the unit & app are the same workload container version.
        """

    @property
    @abc.abstractmethod
    def _app_workload_container_version(self) -> str:
        """Unique identifier for the app's workload container version

        This should match the workload version in the current Juju app charm version.

        This identifier should be comparable to `_unit_workload_container_versions` to determine if
        the app & unit are the same workload container version.
        """

    @abc.abstractmethod
    def reconcile_partition(self, *, action_event: ops.ActionEvent = None) -> None:
        """If ready, allow next unit to upgrade."""

    @property
    @abc.abstractmethod
    def authorized(self) -> bool:
        """Whether this unit is authorized to upgrade

        Only applies to machine charm
        """

    @abc.abstractmethod
    def upgrade_unit(self, *, snap: OpenSearchDistribution) -> None:
        """Upgrade this unit.

        Only applies to machine charm
        """

    def pre_upgrade_check(self) -> None:
        """Check if this app is ready to upgrade

        Runs before any units are upgraded

        Does *not* run during rollback

        On machines, this runs before any units are upgraded (after `juju refresh`)
        On machines & Kubernetes, this also runs during pre-upgrade-check action

        Can run on leader or non-leader unit

        Raises:
            PrecheckFailed: App is not ready to upgrade

        TODO Kubernetes: Run (some) checks after `juju refresh` (in case user forgets to run
        pre-upgrade-check action). Note: 1 unit will upgrade before we can run checks (checks may
        need to be modified).
        See https://chat.canonical.com/canonical/pl/cmf6uhm1rp8b7k8gkjkdsj4mya
        """
        logger.debug("Running pre-upgrade checks")

        try:
            health = self._charm.health.get(
                local_app_only=False,
                wait_for_green_first=True,
            )
            allowed_states = [HealthColors.GREEN]
            if self.in_progress and not self._charm.opensearch.is_started():
                # If the cluster is in the middle of the upgrade, we may have some replicas being
                # unassigned but cannot rellocate as cluster routing is set only for primaries.
                # For that, we use self.in_progress and distro's is_started, so we can tolerate
                # unassigned replicas after this unit has been stopped.
                allowed_states.extend([HealthColors.YELLOW, HealthColors.YELLOW_TEMP])
            if health not in allowed_states:
                raise PrecheckFailed(f"Cluster health is {health} instead of green")

            online_nodes = ClusterTopology.nodes(
                self._charm.opensearch,
                True,
                hosts=self._charm.alt_hosts,
            )
            if (
                not self._charm.is_every_unit_marked_as_started()
                or len([node for node in online_nodes if node.app_name == self._charm.app.name])
                < self._charm.app.planned_units()
            ):
                raise PrecheckFailed("Not all units are online for the current app.")

            if not self._charm.backup.is_idle_or_not_set():
                raise PrecheckFailed("Backup or restore is in progress")

        except OpenSearchHttpError:
            raise PrecheckFailed("Cluster is unreachable")
