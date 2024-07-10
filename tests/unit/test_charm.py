# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile
from os.path import exists
from unittest.mock import MagicMock, patch

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.opensearch_internal_data import Scope
from helpers import create_x509_resources
from unit.lib.test_opensearch_base_charm import TestOpenSearchBaseCharm


class TestCharm(TestOpenSearchBaseCharm):
    def setUp(self):
        super().setUp()

    @patch("os.chown")
    @patch("pwd.getpwnam")
    @patch("grp.getgrnam")
    def test_store_tls_resources(self, grp_getgrnam, pwd_getpwnam, os_chown):
        """Test the storing of TLS resources."""
        self.charm.tls.certs_path = MagicMock()
        self.charm.tls.jdk_path = MagicMock()

        with tempfile.TemporaryDirectory() as tmp_dir:
            self.charm.tls.certs_path = tmp_dir

            unit_resources = create_x509_resources()

            self.secret_store.put_object(
                Scope.UNIT, CertType.UNIT_TRANSPORT, {"keystore-password-unit-transport": "123"}
            )
            self.secret_store.put_object(
                Scope.APP, CertType.APP_ADMIN, {"keystore-password-app-admin": "123"}
            )

            self.charm.tls.store_new_tls_resources(
                CertType.UNIT_TRANSPORT,
                {
                    "ca-cert": "ca",
                    "cert": unit_resources.cert,
                    "key": unit_resources.key,
                },
            )

            self.assertTrue(exists(f"{tmp_dir}/unit-transport.p12"))

            admin_resources = create_x509_resources()

            self.charm.tls.store_new_tls_resources(
                CertType.APP_ADMIN,
                {
                    "ca-cert": "ca",
                    "cert": admin_resources.cert,
                    "chain": admin_resources.cert,
                    "key": admin_resources.key,
                },
            )

            self.assertTrue(exists(f"{tmp_dir}/chain.pem"))
            self.assertTrue(exists(f"{tmp_dir}/unit-transport.p12"))
