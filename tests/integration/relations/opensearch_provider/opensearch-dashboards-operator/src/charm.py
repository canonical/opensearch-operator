#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for Apache Opensearch Dashboards."""

import logging
import time

from charms.rolling_ops.v0.rollingops import RollingOpsManager
from core.cluster import ClusterState
from events.password_actions import PasswordActionEvents
from events.requirer import RequirerEvents

# from events.provider import ProviderEvents
from events.tls import TLSEvents
from literals import CHARM_KEY, CHARM_USERS, PEER, RESTART_TIMEOUT, SUBSTRATE
from managers.config import ConfigManager
from managers.tls import TLSManager
from ops.charm import CharmBase, InstallEvent, SecretChangedEvent
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus
from workload import ODWorkload

# from events.upgrade import ODUpgradeEvents, OpensearchDasboardsDependencyModel


logger = logging.getLogger(__name__)


class OpensearchDasboardsCharm(CharmBase):
    """Charmed Operator for Opensearch Dashboards."""

    def __init__(self, *args):
        super().__init__(*args)
        self.name = CHARM_KEY
        self.state = ClusterState(self, substrate=SUBSTRATE)
        self.workload = ODWorkload()

        # --- CHARM EVENT HANDLERS ---

        self.password_action_events = PasswordActionEvents(self)
        self.tls_events = TLSEvents(self)
        self.requirer_events = RequirerEvents(self)
        # self.upgrade_events = ODUpgradeEvents(
        #     self,
        #     dependency_model=OpensearchDasboardsDependencyModel(
        #         **DEPENDENCIES  # pyright: ignore[reportGeneralTypeIssues]
        #     ),
        # )

        # --- MANAGERS ---

        self.tls_manager = TLSManager(
            state=self.state, workload=self.workload, substrate=SUBSTRATE
        )
        self.config_manager = ConfigManager(
            state=self.state, workload=self.workload, substrate=SUBSTRATE, config=self.config
        )

        # --- LIB EVENT HANDLERS ---

        self.restart = RollingOpsManager(self, relation="restart", callback=self._restart)

        # --- CORE EVENTS ---

        self.framework.observe(getattr(self.on, "install"), self._on_install)

        self.framework.observe(getattr(self.on, "start"), self._start)

        self.framework.observe(
            getattr(self.on, "update_status"), self._on_cluster_relation_changed
        )
        self.framework.observe(
            getattr(self.on, "leader_elected"), self._on_cluster_relation_changed
        )
        self.framework.observe(
            getattr(self.on, "config_changed"), self._on_cluster_relation_changed
        )

        self.framework.observe(
            getattr(self.on, f"{PEER}_relation_changed"), self._on_cluster_relation_changed
        )
        self.framework.observe(
            getattr(self.on, f"{PEER}_relation_joined"), self._on_cluster_relation_changed
        )
        self.framework.observe(
            getattr(self.on, f"{PEER}_relation_departed"), self._on_cluster_relation_changed
        )

        self.framework.observe(getattr(self.on, "secret_changed"), self._on_secret_changed)

    # --- CORE EVENT HANDLERS ---

    def _on_install(self, event: InstallEvent) -> None:
        """Handler for the `on_install` event."""
        self.unit.status = MaintenanceStatus("installing Opensearch Dashboards...")

        install = self.workload.install()
        if not install:
            self.unit.status = BlockedStatus("unable to install Opensearch Dashboards")

        # don't complete install until passwords set
        if not self.state.peer_relation:
            self.unit.status = WaitingStatus("waiting for peer relation")
            event.defer()
            return

        if self.unit.is_leader() and not self.state.cluster.internal_user_credentials:
            for user in CHARM_USERS:
                self.state.cluster.update({f"{user}-password": self.workload.generate_password()})

    def _on_cluster_relation_changed(self, event: EventBase) -> None:
        """Generic handler for all 'something changed, update' events across all relations."""
        # not all methods called
        if not self.state.peer_relation:
            return

        # attempt startup of server
        if not self.state.unit_server.started:
            self.init_server()

        # don't delay scale-down leader ops by restarting dying unit
        if getattr(event, "departing_unit", None) == self.unit:
            return

        if (
            self.config_manager.config_changed()
            and self.state.unit_server.started
            # and self.upgrade_events.idle
        ):
            self.on[f"{self.restart.name}"].acquire_lock.emit()

    def _on_secret_changed(self, event: SecretChangedEvent):
        """Reconfigure services on a secret changed event."""
        if not event.secret.label:
            return

        if not self.state.cluster.relation:
            return

        if event.secret.label == self.state.cluster.data_interface._generate_secret_label(
            PEER,
            self.state.cluster.relation.id,
            None,  # type:ignore noqa
        ):  # Changes with the soon upcoming new version of DP-libs STILL within this POC
            if (
                self.config_manager.config_changed()
                and self.state.unit_server.started
                # and self.upgrade_events.idle
            ):
                logger.info(f"Secret {event.secret.label} changed.")

    def _start(self, event: EventBase) -> None:
        """Forces a rolling-restart event.

        Necessary for ensuring that `on_start` restarts roll.
        """
        # if not self.state.peer_relation or not self.state.stable or not self.upgrade_events.idle:
        self.unit.status = MaintenanceStatus("Starting...")
        if not self.state.peer_relation or not self.state.stable:
            event.defer()
            return

        # not needed during application init
        # only needed for scenarios where the LXD goes down (e.g PC shutdown)
        if not self.workload.alive():
            self.on[f"{self.restart.name}"].acquire_lock.emit()
        else:
            self.unit.status = ActiveStatus()

    def _restart(self, event: EventBase) -> None:
        """Handler for emitted restart events."""
        # if not self.state.stable or not self.upgrade_events.idle:
        if not self.state.stable:
            event.defer()
            return

        logger.info(f"{self.unit.name} (re)starting...")
        self.workload.restart()

        start_time = time.time()
        while not self.workload.alive() and time.time() - start_time < RESTART_TIMEOUT:
            time.sleep(5)

        self.unit.status = ActiveStatus()

    # --- CONVENIENCE METHODS ---

    def init_server(self):
        """Calls startup functions for server start."""
        # don't run if leader has not yet created passwords
        if not self.state.cluster.internal_user_credentials:
            self.unit.status = MaintenanceStatus("waiting for passwords to be created")
            return

        self.unit.status = MaintenanceStatus("starting Opensearch Dashboards server")
        logger.info(f"{self.unit.name} initializing...")

        logger.debug("setting properties")
        self.config_manager.set_dashboard_properties()

        logger.debug("starting Opensearch Dashboards service")
        self.workload.start()
        self.unit.status = ActiveStatus()

        # unit flags itself as 'started' so it can be retrieved by the leader
        logger.info(f"{self.unit.name} started")

        # added here in case a `restart` was missed
        self.state.unit_server.update(
            {
                "state": "started",
            }
        )


if __name__ == "__main__":
    main(OpensearchDasboardsCharm)
