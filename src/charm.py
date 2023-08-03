#!/usr/bin/env python3

# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""
import logging
from os import remove
from os.path import exists
from typing import Dict

from charms.opensearch.v0.constants_charm import InstallError, InstallProgress
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_security import to_pkcs8
from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm
from charms.opensearch.v0.opensearch_exceptions import OpenSearchInstallError
from ops.charm import InstallEvent
from ops.main import main
from ops.model import BlockedStatus, MaintenanceStatus
from overrides import override

from opensearch import OpenSearchSnap

logger = logging.getLogger(__name__)


class OpenSearchOperatorCharm(OpenSearchBaseCharm):
    """This class represents the machine charm for OpenSearch."""

    def __init__(self, *args):
        super().__init__(*args, distro=OpenSearchSnap)  # OpenSearchTarball

        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, _: InstallEvent) -> None:
        """Handle the install event."""
        self.unit.status = MaintenanceStatus(InstallProgress)
        try:
            self.opensearch.install()
            self.status.clear(InstallProgress)
        except OpenSearchInstallError:
            self.unit.status = BlockedStatus(InstallError)

    @override
    def _store_tls_resources(
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
