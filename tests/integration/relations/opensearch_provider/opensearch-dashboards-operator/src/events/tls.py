#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handler for related applications on the `certificates` relation interface."""
import base64
import logging
import re
from typing import TYPE_CHECKING

from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    TLSCertificatesRequiresV3,
    generate_csr,
    generate_private_key,
)
from ops.charm import ActionEvent, RelationCreatedEvent, RelationJoinedEvent
from ops.framework import EventBase, Object

if TYPE_CHECKING:
    from charm import OpensearchDasboardsCharm

logger = logging.getLogger(__name__)


class TLSEvents(Object):
    """Event handlers for related applications on the `certificates` relation interface."""

    def __init__(self, charm):
        super().__init__(charm, "tls")
        self.charm: "OpensearchDasboardsCharm" = charm
        self.certificates = TLSCertificatesRequiresV3(self.charm, "certificates")

        self.framework.observe(
            getattr(self.charm.on, "certificates_relation_created"),
            self._on_certs_relation_created,
        )
        self.framework.observe(
            getattr(self.charm.on, "certificates_relation_joined"), self._on_certs_relation_joined
        )
        self.framework.observe(
            getattr(self.certificates.on, "certificate_available"), self._on_certificate_available
        )
        self.framework.observe(
            getattr(self.certificates.on, "certificate_expiring"), self._on_certificate_expiring
        )
        self.framework.observe(
            getattr(self.charm.on, "certificates_relation_broken"), self._on_certs_relation_broken
        )

        self.framework.observe(
            getattr(self.charm.on, "set_tls_private_key_action"), self._set_tls_private_key
        )

    def _on_certs_relation_created(self, event: RelationCreatedEvent) -> None:
        """Handler for `certificates_relation_created` event."""
        if not self.charm.unit.is_leader():
            return

        self.charm.state.cluster.update({"tls": "enabled", "switching-encryption": "started"})

    def _on_certs_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Handler for `certificates_relation_joined` event."""
        if not self.charm.state.cluster.tls:
            logger.debug(
                "certificates relation joined - tls not enabled and not switching encryption - deferring"
            )
            event.defer()
            return

        # generate unit private key if not already created by action
        if not self.charm.state.unit_server.private_key:
            self.charm.state.unit_server.update(
                {"private-key": generate_private_key().decode("utf-8")}
            )

        # generate unit key/truststore password if not already created by action
        # self.charm.state.unit_server.update(
        #     {
        #         "keystore-password": self.charm.state.unit_server.keystore_password
        #         or self.charm.workload.generate_password(),
        #         "truststore-password": self.charm.state.unit_server.truststore_password
        #         or self.charm.workload.generate_password(),
        #     }
        # )

        csr = generate_csr(
            private_key=self.charm.state.unit_server.private_key.encode("utf-8"),
            subject=self.charm.state.unit_server.host,
            sans_ip=self.charm.state.unit_server.sans.get("sans_ip", []),
            sans_dns=self.charm.state.unit_server.sans.get("sans_dns", []),
        )

        self.charm.state.unit_server.update({"csr": csr.decode("utf-8").strip()})

        self.certificates.request_certificate_creation(certificate_signing_request=csr)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handler for `certificates_available` event after provider updates signed certs."""
        # avoid setting tls files and restarting
        if event.certificate_signing_request != self.charm.state.unit_server.csr:
            logger.error("Can't use certificate, found unknown CSR")
            return

        # if certificate already exists, this event must be new, flag restart
        if self.charm.state.unit_server.certificate:
            self.charm.on[f"{self.charm.restart.name}"].acquire_lock.emit()

        self.charm.state.unit_server.update(
            {"certificate": event.certificate, "ca-cert": event.ca}
        )

        self.charm.tls_manager.set_private_key()
        self.charm.tls_manager.set_ca()
        self.charm.tls_manager.set_certificate()
        # self.charm.tls_manager.set_truststore()
        # self.charm.tls_manager.set_p12_keystore()

        self.charm.on[f"{self.charm.restart.name}"].acquire_lock.emit()

    def _on_certificate_expiring(self, _: EventBase) -> None:
        """Handler for `certificates_expiring` event when certs need renewing."""
        if not (self.charm.state.unit_server.private_key or self.charm.state.unit_server.csr):
            logger.error("Missing unit private key and/or old csr")
            return

        new_csr = generate_csr(
            private_key=self.charm.state.unit_server.private_key.encode("utf-8"),
            subject=self.charm.state.unit_server.host,
            sans_ip=self.charm.state.unit_server.sans["sans_ip"],
            sans_dns=self.charm.state.unit_server.sans["sans_dns"],
        )

        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=self.charm.state.unit_server.csr.encode("utf-8"),
            new_certificate_signing_request=new_csr,
        )

        self.charm.state.unit_server.update({"csr": new_csr.decode("utf-8").strip()})

    def _on_certs_relation_broken(self, _) -> None:
        """Handler for `certificates_relation_broken` event."""
        self.charm.state.unit_server.update({"csr": "", "certificate": "", "ca-cert": ""})

        # remove all existing keystores from the unit so we don't preserve certs
        self.charm.tls_manager.remove_cert_files()

        if not self.charm.unit.is_leader():
            return

        self.charm.state.cluster.update({"tls": "", "switching-encryption": "started"})

    def _set_tls_private_key(self, event: ActionEvent) -> None:
        """Handler for `set-tls-privat-key` event when user manually specifies private-keys for a unit."""
        key = event.params.get("internal-key") or generate_private_key().decode("utf-8")
        private_key = (
            key
            if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", key)
            else base64.b64decode(key).decode("utf-8")
        )

        self.charm.state.unit_server.update({"private-key": private_key})
        self._on_certificate_expiring(event)
