#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handlers for password-related Juju Actions."""
import logging
from typing import TYPE_CHECKING

from literals import CHARM_USERS
from ops.charm import ActionEvent
from ops.framework import Object

if TYPE_CHECKING:
    from charm import OpensearchDasboardsCharm

logger = logging.getLogger(__name__)


class PasswordActionEvents(Object):
    """Event handlers for password-related Juju Actions."""

    def __init__(self, charm):
        super().__init__(charm, "password_events")
        self.charm: "OpensearchDasboardsCharm" = charm

        self.framework.observe(
            getattr(self.charm.on, "get_password_action"), self._get_password_action
        )
        self.framework.observe(
            getattr(self.charm.on, "set_password_action"), self._set_password_action
        )

    def _get_password_action(self, event: ActionEvent) -> None:
        """Handler for get-super-password action event."""
        username = event.params.get("username", CHARM_USERS[0])
        event.set_results(
            {f"{username}-password": self.charm.state.cluster.internal_user_credentials[username]}
        )

    def _set_password_action(self, event: ActionEvent) -> None:
        """Handler for set-password action.

        Set the password for a specific user, if no passwords are passed, generate them.
        """
        if not self.charm.unit.is_leader():
            msg = "Password rotation must be called on leader unit"
            logger.error(msg)
            event.fail(msg)
            return

        username = event.params.get("username", "admin")
        if username not in CHARM_USERS:
            msg = f"The action can be run only for users used by the charm: {CHARM_USERS} not {username}."
            logger.error(msg)
            event.fail(msg)
            return

        new_password = event.params.get("password", self.charm.workload.generate_password())

        # Passwords should not be the same.
        if new_password in self.charm.state.cluster.internal_user_credentials.values():
            event.log("The old and new passwords are equal.")
            event.set_results({f"{username}-password": new_password})
            return

        # Store those passwords on application databag
        self.charm.state.cluster.update({f"{username}-password": new_password})

        # implicitly calls config_changed on leader, other units will get it because of
        # relation-data change with new passwords
        # self.charm._on_cluster_relation_changed(event)
        event.set_results({f"{username}-password": new_password})
