#!/usr/bin/env python3

# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""
import logging
import typing
from os import remove
from os.path import exists
from typing import Dict

import ops
from charms.opensearch.v0.constants_charm import InstallError, InstallProgress
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_security import to_pkcs8
from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm
from charms.opensearch.v0.opensearch_exceptions import OpenSearchInstallError
from ops.charm import InstallEvent
from ops.main import main
from ops.model import BlockedStatus, MaintenanceStatus
from overrides import override

import machine_upgrade
import upgrade
from opensearch import OpenSearchSnap

logger = logging.getLogger(__name__)


class OpenSearchOperatorCharm(OpenSearchBaseCharm):
    """This class represents the machine charm for OpenSearch."""

    def __init__(self, *args):
        super().__init__(*args, distro=OpenSearchSnap)  # OpenSearchTarball

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.upgrade_charm, self._on_upgrade_charm)
        self.framework.observe(
            self.on[upgrade.PEER_RELATION_ENDPOINT_NAME].relation_created,
            self._on_upgrade_peer_relation_created,
        )
        self.framework.observe(
            self.on[upgrade.PEER_RELATION_ENDPOINT_NAME].relation_changed, self._reconcile_upgrade
        )
        self.framework.observe(
            self.on[upgrade.RESUME_ACTION_NAME].action, self._on_resume_upgrade_action
        )
        self.framework.observe(self.on["force-upgrade"].action, self._on_force_upgrade_action)

    @property
    def _upgrade(self) -> typing.Optional[machine_upgrade.Upgrade]:
        try:
            return machine_upgrade.Upgrade(self)
        except upgrade.PeerRelationNotReady:
            pass

    def _on_install(self, _: InstallEvent) -> None:
        """Handle the install event."""
        self.unit.status = MaintenanceStatus(InstallProgress)
        try:
            self.opensearch.install()
            self.status.clear(InstallProgress)
        except OpenSearchInstallError:
            self.unit.status = BlockedStatus(InstallError)

    def _on_upgrade_peer_relation_created(self, _) -> None:
        if self._unit_lifecycle.authorized_leader:
            if not self._upgrade.in_progress:
                # Save versions on initial start
                self._upgrade.set_versions_in_app_databag()

    def _reconcile_upgrade(self, _=None):
        """Handle upgrade events."""
        if not self._upgrade:
            logger.debug("Peer relation not available")
            return
        if not self._upgrade.versions_set:
            logger.debug("Peer relation not ready")
            return
        if self._unit_lifecycle.authorized_leader and not self._upgrade.in_progress:
            # Run before checking `self._upgrade.is_compatible` in case incompatible upgrade was
            # forced & completed on all units.
            self._upgrade.set_versions_in_app_databag()
        if not self._upgrade.is_compatible:
            self._set_upgrade_status()
            return
        if self._upgrade.unit_state == "outdated":
            if self._upgrade.authorized:
                self._set_upgrade_status()
                self._upgrade_opensearch_event.emit()
            else:
                self._set_upgrade_status()
                logger.debug("Waiting to upgrade")
                return
        self._set_upgrade_status()

    def _set_upgrade_status(self):
        # Set/clear upgrade unit status if no other unit status
        if isinstance(self.unit.status, ops.ActiveStatus) or (
            isinstance(self.unit.status, ops.WaitingStatus)
            and self.unit.status.message.startswith("Charmed operator upgraded.")
        ):
            self.status.set(self._upgrade.get_unit_juju_status() or ops.ActiveStatus())
        if not self.unit.is_leader():
            return
        # Set upgrade app status
        if status := self._upgrade.app_status:
            self.status.set(status, app=True)
        else:
            # Clear upgrade app status
            if (
                isinstance(self.app.status, ops.BlockedStatus)
                or isinstance(self.app.status, ops.MaintenanceStatus)
            ) and self.app.status.message.startswith("Upgrad"):
                self.status.set(ops.ActiveStatus(), app=True)

    def _on_upgrade_charm(self, _):
        if self._unit_lifecycle.authorized_leader:
            if not self._upgrade.in_progress:
                logger.info("Charm upgraded. OpenSearch version unchanged")
            self._upgrade.upgrade_resumed = False
            # Only call `_reconcile_upgrade` on leader unit to avoid race conditions with `upgrade_resumed`
            self._reconcile_upgrade()

    def _on_resume_upgrade_action(self, event: ops.ActionEvent) -> None:
        if not self._unit_lifecycle.authorized_leader:
            message = f"Must run action on leader unit. (e.g. `juju run {self.app.name}/leader {upgrade.RESUME_ACTION_NAME}`)"
            logger.debug(f"Resume upgrade event failed: {message}")
            event.fail(message)
            return
        if not self._upgrade or not self._upgrade.in_progress:
            message = "No upgrade in progress"
            logger.debug(f"Resume upgrade event failed: {message}")
            event.fail(message)
            return
        self._upgrade.reconcile_partition(action_event=event)

    def _on_force_upgrade_action(self, event: ops.ActionEvent) -> None:
        if not self._upgrade or not self._upgrade.in_progress:
            message = "No upgrade in progress"
            logger.debug(f"Force upgrade event failed: {message}")
            event.fail(message)
            return
        if not self._upgrade.upgrade_resumed:
            message = f"Run `juju run {self.app.name}/leader resume-upgrade` before trying to force upgrade"
            logger.debug(f"Force upgrade event failed: {message}")
            event.fail(message)
            return
        if self._upgrade.unit_state != "outdated":
            message = "Unit already upgraded"
            logger.debug(f"Force upgrade event failed: {message}")
            event.fail(message)
            return
        logger.debug("Forcing upgrade")
        event.log(f"Forcefully upgrading {self.unit.name}")
        self._upgrade_opensearch_event.emit(ignore_lock=event.params["ignore-lock"])
        event.set_results({"result": f"Forcefully upgraded {self.unit.name}"})
        logger.debug("Forced upgrade")

    @override
    def store_tls_resources(
        self, cert_type: CertType, secrets: Dict[str, any], override_admin: bool = True
    ):
        """Write certificates and keys on disk."""
        certs_dir = self.opensearch.paths.certs

        if not secrets.get("key"):
            logging.error("TLS key not found, quitting.")
            return

        self.opensearch.write_file(
            f"{certs_dir}/{cert_type}.key",
            to_pkcs8(secrets["key"], secrets.get("key-password")),
        )
        self.opensearch.write_file(f"{certs_dir}/{cert_type}.cert", secrets["cert"])
        self.opensearch.write_file(f"{certs_dir}/root-ca.cert", secrets["ca-cert"], override=False)

        if cert_type == CertType.APP_ADMIN:
            self.opensearch.write_file(
                f"{certs_dir}/chain.pem",
                secrets["chain"],
                override=override_admin,
            )

    @override
    def _are_all_tls_resources_stored(self):
        """Check if all TLS resources are stored on disk."""
        certs_dir = self.opensearch.paths.certs
        for cert_type in [CertType.APP_ADMIN, CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            for extension in ["key", "cert"]:
                if not exists(f"{certs_dir}/{cert_type}.{extension}"):
                    return False

        return exists(f"{certs_dir}/chain.pem") and exists(f"{certs_dir}/root-ca.cert")

    @override
    def _delete_stored_tls_resources(self):
        """Delete the TLS resources of the unit that are stored on disk."""
        certs_dir = self.opensearch.paths.certs
        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            for extension in ["key", "cert"]:
                try:
                    remove(f"{certs_dir}/{cert_type}.{extension}")
                except OSError:
                    # thrown if file not exists, ignore
                    pass


if __name__ == "__main__":
    main(OpenSearchOperatorCharm)
