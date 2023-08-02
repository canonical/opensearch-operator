# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile
from os import listdir
from os.path import isfile, join
from unittest.mock import MagicMock, patch

from charms.opensearch.v0.constants_tls import CertType
from helpers import create_utf8_encoded_private_key
from unit.lib.test_opensearch_base_charm import TestOpenSearchBaseCharm


class TestCharm(TestOpenSearchBaseCharm):
    def setUp(self):
        super().setUp()

    @patch("os.chown")
    @patch("pwd.getpwnam")
    @patch("grp.getgrnam")
    def test_store_tls_resources(self, grp_getgrnam, pwd_getpwnam, os_chown):
        """Test the storing of TLS resources."""
        self.opensearch.paths = MagicMock()

        with tempfile.TemporaryDirectory() as tmp_dir:
            self.opensearch.paths.certs = tmp_dir

            self.charm._store_tls_resources(
                CertType.UNIT_TRANSPORT,
                {
                    "ca-cert": "ca",
                    "cert": "cert_transport",
                    "key": create_utf8_encoded_private_key(),
                },
            )

            stored_files = [f for f in listdir(tmp_dir) if isfile(join(tmp_dir, f))]

            t_prefix = CertType.UNIT_TRANSPORT.val
            self.assertCountEqual(
                stored_files, ["root-ca.cert", f"{t_prefix}.cert", f"{t_prefix}.key"]
            )

            self.charm._store_tls_resources(
                CertType.APP_ADMIN,
                {
                    "ca-cert": "ca",
                    "cert": "cert_admin",
                    "chain": "chain",
                    "key": create_utf8_encoded_private_key(),
                },
            )

            stored_files = [f for f in listdir(tmp_dir) if isfile(join(tmp_dir, f))]

            a_prefix = CertType.APP_ADMIN.val
            self.assertCountEqual(
                stored_files,
                [
                    "root-ca.cert",
                    f"{a_prefix}.cert",
                    f"{a_prefix}.key",
                    "chain.pem",
                    f"{t_prefix}.cert",
                    f"{t_prefix}.key",
                ],
            )

    @patch("os.chown")
    @patch("pwd.getpwnam")
    @patch("grp.getgrnam")
    def test_are_all_tls_resources_stored(self, grp_getgrnam, pwd_getpwnam, os_chown):
        """Test if all TLS resources are successfully stored."""
        self.opensearch.paths = MagicMock()

        with tempfile.TemporaryDirectory() as tmp_dir:
            self.opensearch.paths.certs = tmp_dir

            self.assertFalse(self.charm._are_all_tls_resources_stored())

            self.charm._store_tls_resources(
                CertType.UNIT_TRANSPORT,
                {
                    "ca-cert": "ca",
                    "cert": "cert_transport",
                    "key": create_utf8_encoded_private_key(),
                },
            )
            self.assertFalse(self.charm._are_all_tls_resources_stored())

            self.charm._store_tls_resources(
                CertType.APP_ADMIN,
                {
                    "ca-cert": "ca",
                    "cert": "cert_admin",
                    "chain": "chain",
                    "key": create_utf8_encoded_private_key(),
                },
            )
            self.assertFalse(self.charm._are_all_tls_resources_stored())

            self.charm._store_tls_resources(
                CertType.UNIT_HTTP,
                {"ca-cert": "ca", "cert": "cert_http", "key": create_utf8_encoded_private_key()},
            )
            self.assertTrue(self.charm._are_all_tls_resources_stored())
