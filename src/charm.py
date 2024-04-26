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
            self.on[upgrade.PRECHECK_ACTION_NAME].action, self._on_pre_upgrade_check_action
        )
        self.framework.observe(
            self.on[upgrade.RESUME_ACTION_NAME].action, self._on_resume_upgrade_action
        )
        self.framework.observe(
            self.on[machine_upgrade.FORCE_ACTION_NAME].action, self._on_force_upgrade_action
        )

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
        self._upgrade.save_snap_revision_after_first_install()
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
            # Side effect: on machines, if charm was upgraded to a charm with the same snap
            # revision, compatibility checks will be skipped.
            # (The only real use case for this would be upgrading the charm code to an incompatible
            # version without upgrading the snap. In that situation, the upgrade may appear
            # successful and the user will not be notified of the charm incompatibility. This case
            # is much less likely than the forced incompatible upgrade & the impact is not as bad
            # as the impact if we did not handle the forced incompatible upgrade case.)
            self._upgrade.set_versions_in_app_databag()
        if not self._upgrade.is_compatible:
            self._set_upgrade_status()
            return
        if self._upgrade.unit_state is upgrade.UnitState.OUTDATED:
            try:
                authorized = self._upgrade.authorized
            except upgrade.PrecheckFailed as exception:
                self._set_upgrade_status()
                self.unit.status = exception.status
                logger.error(
                    f"Rollback with `juju refresh`. Pre-upgrade check failed: {exception.status.message}"
                )
                return
            if authorized:
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
            isinstance(self.unit.status, ops.BlockedStatus)
            and self.unit.status.message.startswith(
                "Rollback with `juju refresh`. Pre-upgrade check failed:"
            )
        ):
            self.status.set(self._upgrade.get_unit_juju_status() or ops.ActiveStatus())
            logger.debug(f"Set unit status to {self.unit.status}")
        if not self.unit.is_leader():
            return
        # Set upgrade app status
        if status := self._upgrade.app_status:
            self.status.set(status, app=True)
            logger.debug(f"Set app status to {self.app.status}")
        else:
            # Clear upgrade app status
            if (
                isinstance(self.app.status, ops.BlockedStatus)
                or isinstance(self.app.status, ops.MaintenanceStatus)
            ) and self.app.status.message.startswith("Upgrad"):
                self.status.set(ops.ActiveStatus(), app=True)
                logger.debug(f"Set app status to {self.app.status}")

    def _on_upgrade_charm(self, _):
        if self._unit_lifecycle.authorized_leader:
            if not self._upgrade.in_progress:
                logger.info("Charm upgraded. OpenSearch version unchanged")
            self._upgrade.upgrade_resumed = False
            # Only call `_reconcile_upgrade` on leader unit to avoid race conditions with
            # `upgrade_resumed`
            self._reconcile_upgrade()

    def _on_pre_upgrade_check_action(self, event: ops.ActionEvent) -> None:
        if not self._unit_lifecycle.authorized_leader:
            message = f"Must run action on leader unit. (e.g. `juju run {self.app.name}/leader {upgrade.PRECHECK_ACTION_NAME}`)"
            logger.debug(f"Pre-upgrade check event failed: {message}")
            event.fail(message)
            return
        if not self._upgrade or self._upgrade.in_progress:
            message = "Upgrade already in progress"
            logger.debug(f"Pre-upgrade check event failed: {message}")
            event.fail(message)
            return
        try:
            self._upgrade.pre_upgrade_check()
        except upgrade.PrecheckFailed as exception:
            message = (
                f"Charm is *not* ready for upgrade. Pre-upgrade check failed: {exception.message}"
            )
            logger.debug(f"Pre-upgrade check event failed: {message}")
            event.fail(message)
            return
        event.set_results({"result": "Charm is ready for upgrade"})
        logger.debug("Pre-upgrade check event succeeded")

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
        # If next to upgrade, upgrade leader unit
        self._reconcile_upgrade()

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
        if self._upgrade.unit_state is not upgrade.UnitState.OUTDATED:
            message = "Unit already upgraded"
            logger.debug(f"Force upgrade event failed: {message}")
            event.fail(message)
            return
        logger.debug("Forcing upgrade")
        event.log(f"Forcefully upgrading {self.unit.name}")
        # TODO: replace `ignore_lock=False` with `event.params["ignore-lock"]` if specification
        # DA091 approved
        # (https://docs.google.com/document/d/1rwnS-deJU9Mzc8BFkl3UGgjZiBa6e3bxoT-6BQo9e3E/edit)
        self._upgrade_opensearch_event.emit(ignore_lock=False)
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
