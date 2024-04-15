# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In-place upgrades

Based off specification: DA058 - In-Place Upgrades - Kubernetes v2
(https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
"""

import abc
import copy
import json
import logging
import pathlib
import typing

import ops
import poetry.core.constraints.version as poetry_version

import workload

logger = logging.getLogger(__name__)

PEER_RELATION_ENDPOINT_NAME = "upgrade-version-a"
RESUME_ACTION_NAME = "resume-upgrade"


def unit_number(unit_: ops.Unit) -> int:
    """Get unit number"""
    return int(unit_.name.split("/")[-1])


class PeerRelationNotReady(Exception):
    """Upgrade peer relation not available (to this unit)"""


class Upgrade(abc.ABC):
    """In-place upgrades"""

    def __init__(self, charm_: ops.CharmBase) -> None:
        relations = charm_.model.relations[PEER_RELATION_ENDPOINT_NAME]
        if not relations:
            raise PeerRelationNotReady
        assert len(relations) == 1
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
    def unit_state(self) -> typing.Optional[str]:
        """Unit upgrade state"""
        return self._unit_databag.get("state")

    @unit_state.setter
    def unit_state(self, value: str) -> None:
        self._unit_databag["state"] = value

    @property
    def is_compatible(self) -> bool:
        """Whether upgrade is supported from previous versions"""
        assert self.versions_set
        try:
            previous_version_strs: typing.Dict[str, str] = json.loads(
                self._app_databag["versions"]
            )
        except KeyError as exception:
            logger.debug("`versions` missing from peer relation", exc_info=exception)
            return False
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
                or previous_versions["workload"].minor != current_versions["workload"].minor
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
        logger.debug(f"{self._app_workload_version=} {self._unit_workload_versions=}")
        return any(
            version != self._app_workload_version
            for version in self._unit_workload_versions.values()
        )

    @property
    def _sorted_units(self) -> typing.List[ops.Unit]:
        """Units sorted from highest to lowest unit number"""
        return sorted((self._unit, *self._peer_relation.units), key=unit_number, reverse=True)

    @abc.abstractmethod
    def _get_unit_healthy_status(
        self, *, workload_status: typing.Optional[ops.StatusBase]
    ) -> ops.StatusBase:
        """Status shown during upgrade if unit is healthy"""

    def get_unit_juju_status(
        self, *, workload_status: typing.Optional[ops.StatusBase]
    ) -> typing.Optional[ops.StatusBase]:
        if self.in_progress:
            return self._get_unit_healthy_status(workload_status=workload_status)

    @property
    def app_status(self) -> typing.Optional[ops.StatusBase]:
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
    def _unit_workload_versions(self) -> typing.Dict[str, str]:
        """{Unit name: unique identifier for unit's workload version}

        If and only if this version changes, the workload will restart (during upgrade or
        rollback).

        On Kubernetes, the workload & charm are upgraded together
        On machines, the charm is upgraded before the workload

        This identifier should be comparable to `_app_workload_version` to determine if the unit &
        app are the same workload version.
        """

    @property
    @abc.abstractmethod
    def _app_workload_version(self) -> str:
        """Unique identifier for the app's workload version

        This should match the workload version in the current Juju app charm version.

        This identifier should be comparable to `_get_unit_workload_version` to determine if the
        app & unit are the same workload version.
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
    def upgrade_unit(self, *, workload_: workload.Workload, tls: bool) -> None:
        """Upgrade this unit.

        Only applies to machine charm
        """
