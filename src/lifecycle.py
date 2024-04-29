# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm lifecycle

https://juju.is/docs/sdk/a-charms-life
"""
import enum
import logging
import typing

import ops

logger = logging.getLogger(__name__)


class _UnitTearingDownAndAppActive(enum.IntEnum):
    """Unit is tearing down and 1+ other units are NOT tearing down"""

    FALSE = 0
    TRUE = 1
    UNKNOWN = 2

    def __bool__(self):
        return self is self.TRUE


class Unit(ops.Object):
    """Unit lifecycle

    NOTE: Instantiate this object before registering event observers.
    """

    _stored = ops.StoredState()

    def __init__(
        self,
        charm: ops.CharmBase,
        subordinated_relation_endpoint_names: typing.Optional[typing.Iterable[str]],
    ):
        """Unit lifecycle

        NOTE: Instantiate this object before registering event observers.

        Args:
            charm: Charm
            subordinated_relation_endpoint_names: Endpoint names for relations between subordinate
                and principal charms where charm is subordinate

                Does NOT include relations where charm is principal
        """
        super().__init__(charm, str(type(self)))
        if subordinated_relation_endpoint_names is None:
            subordinated_relation_endpoint_names = ()
        self._subordinate = bool(subordinated_relation_endpoint_names)
        self._charm = charm
        for relation_endpoint in self.model.relations:
            if relation_endpoint in subordinated_relation_endpoint_names:
                self.framework.observe(
                    self._charm.on[relation_endpoint].relation_departed,
                    self._on_subordinate_relation_departed,
                )
                self.framework.observe(
                    self._charm.on[relation_endpoint].relation_broken,
                    self._on_subordinate_relation_broken,
                )
            else:
                self.framework.observe(
                    self._charm.on[relation_endpoint].relation_departed, self._on_relation_departed
                )

    @property
    def _unit_tearing_down_and_app_active(self) -> _UnitTearingDownAndAppActive:
        """Whether unit is tearing down and 1+ other units are NOT tearing down"""
        try:
            return _UnitTearingDownAndAppActive(self._stored.unit_tearing_down_and_app_active)
        except AttributeError:
            return _UnitTearingDownAndAppActive.FALSE

    @_unit_tearing_down_and_app_active.setter
    def _unit_tearing_down_and_app_active(self, enum_member: _UnitTearingDownAndAppActive) -> None:
        self._stored.unit_tearing_down_and_app_active = enum_member.value

    def _on_relation_departed(self, event: ops.RelationDepartedEvent) -> None:
        if event.departing_unit == self._charm.unit:
            self._unit_tearing_down_and_app_active = _UnitTearingDownAndAppActive.TRUE

    def _on_subordinate_relation_departed(self, _) -> None:
        if self._unit_tearing_down_and_app_active:
            return
        # We cannot use the output of `goal-state` until we get the *-relation-broken event.
        # During *-relation-departed, it is not guaranteed that all units that are tearing down
        # report "dying" status. It is guaranteed during the *-relation-broken event.
        self._unit_tearing_down_and_app_active = _UnitTearingDownAndAppActive.UNKNOWN

    def _on_subordinate_relation_broken(self, event: ops.RelationBrokenEvent) -> None:
        if self._unit_tearing_down_and_app_active:
            return
        # Workaround for subordinate charms: https://bugs.launchpad.net/juju/+bug/2025676
        # A subordinate unit will get a *-relation-departed event where
        # `event.departing_unit == self._charm.unit` is `True` in any of these situations:
        # 1. `juju remove-relation` with principal charm or `juju remove-application` for
        #         subordinate charm
        # 2. `juju remove-application` for principal charm
        # 3. App has 1 unit, then `juju remove-unit` for principal charm
        # 4. App has 2+ units, then `juju remove-unit` for principal charm

        # In situations #1-3, all units of the subordinate charm are tearing down.
        # In situation #4, there will be 1+ units that are not tearing down.
        # In situations #1-3, the current leader will not be replaced by another leader after
        # it tears down, so it should act as a leader (e.g. handle user cleanup on
        # *-relation-broken) now.
        output = self._charm.model._backend._run("goal-state", return_output=True, use_json=True)
        principal_unit_statuses = set()
        for unit_or_app, info in output["relations"].items():
            unit_or_app: str
            info: dict
            # Filter out app info & units for other apps
            if unit_or_app.startswith(f"{event.relation.app}/"):
                principal_unit_statuses.add(info["status"])

        # In situation #1, NO `principal_unit_statuses` will be "dying"
        # In situation #2 and #3, all `principal_unit_statuses` will be "dying"
        if "dying" in principal_unit_statuses and principal_unit_statuses != {"dying"}:
            # Situation #4
            self._unit_tearing_down_and_app_active = _UnitTearingDownAndAppActive.TRUE
        else:
            # Situation #1, #2, or #3
            self._unit_tearing_down_and_app_active = _UnitTearingDownAndAppActive.FALSE

    @property
    def tearing_down_and_app_active(self) -> bool:
        """Whether unit is tearing down and 1+ other units are NOT tearing down

        Cannot be called on subordinate charms
        """
        assert not self._subordinate
        return self._unit_tearing_down_and_app_active is not _UnitTearingDownAndAppActive.FALSE

    @property
    def authorized_leader(self) -> bool:
        """Whether unit is authorized to act as leader

        Returns `False` if unit is tearing down and will be replaced by another leader

        For subordinate charms, this should not be accessed during *-relation-departed.

        Teardown event sequence:
        *-relation-departed -> *-relation-broken
        stop
        remove

        Workaround for https://bugs.launchpad.net/juju/+bug/1979811
        (Unit receives *-relation-broken event when relation still exists [for other units])
        """
        if not self._charm.unit.is_leader():
            return False
        if self._unit_tearing_down_and_app_active is _UnitTearingDownAndAppActive.UNKNOWN:
            logger.warning(
                f"{type(self)}.authorized_leader should not be accessed during *-relation-departed for subordinate relations"
            )
        return self._unit_tearing_down_and_app_active is _UnitTearingDownAndAppActive.FALSE
