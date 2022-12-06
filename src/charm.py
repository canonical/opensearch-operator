#!/usr/bin/env python3

# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""
import logging
from os.path import exists
from typing import Dict

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_security import to_pkcs8
from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm
from ops.main import main
from overrides import override

from opensearch import OpenSearchTarball

logger = logging.getLogger(__name__)


class OpenSearchOperatorCharm(OpenSearchBaseCharm):
    """This class represents the machine charm for OpenSearch."""

    def __init__(self, *args):
        super().__init__(*args, distro=OpenSearchTarball)  # OpenSearchSnap

    @override
    def _store_tls_resources(
        self, cert_type: CertType, secrets: Dict[str, any], override_admin: bool = True
    ):
        """Write certificates and keys on disk."""
        certs_dir = self.opensearch.paths.certs

        self.opensearch.write_file(
            f"{certs_dir}/{cert_type.val}.key",
            to_pkcs8(secrets["key"], secrets.get("key-password")),
        )
        self.opensearch.write_file(f"{certs_dir}/{cert_type.val}.cert", secrets["cert"])
        self.opensearch.write_file(f"{certs_dir}/root-ca.cert", secrets["ca"], override=False)

        if cert_type == CertType.APP_ADMIN:
            self.opensearch.write_file(
                f"{certs_dir}/chain.pem",
                "\n".join(secrets["chain"][::-1]),
                override=override_admin,
            )

    @override
    def _are_all_tls_resources_stored(self):
        """Check if all TLS resources are stored on disk."""
        certs_dir = self.opensearch.paths.certs
        for cert_type in [CertType.APP_ADMIN, CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            for extension in ["key", "cert"]:
                if not exists(f"{certs_dir}/{cert_type.val}.{extension}"):
                    return False

        return exists(f"{certs_dir}/chain.pem") and exists(f"{certs_dir}/root-ca.cert")


if __name__ == "__main__":
    main(OpenSearchOperatorCharm)
