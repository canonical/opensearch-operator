# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile
from os import listdir
from os.path import isfile, join
from unittest.mock import MagicMock, patch

from charms.opensearch.v0.constants_tls import CertType
from helpers import create_utf8_encoded_private_key, create_x509_resources
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

        with tempfile.TemporaryDirectory() as tmp_dir:
            self.charm.tls.certs_path = tmp_dir

            ca_resources = create_x509_resources()

            self.charm.tls.store_new_tls_resources(
                CertType.UNIT_TRANSPORT,
                {
                    "ca-cert": "ca",
                    "cert": ca_resources.cert,
                    "key": ca_resources.key,
                },
            )

            stored_files = [f for f in listdir(tmp_dir) if isfile(join(tmp_dir, f))]

            t_prefix = CertType.UNIT_TRANSPORT.val
            self.assertCountEqual(
                stored_files, ["ca.p12", f"{t_prefix}.p12"]
            )

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

            stored_files = [f for f in listdir(tmp_dir) if isfile(join(tmp_dir, f))]

            self.assertCountEqual(
                stored_files,
                [
                    "root-ca.cert",
                    "ca.p12",
                    "admin-cert-chain.pem",
                    f"{t_prefix}.p12",
                ],
            )

    @patch("os.chown")
    @patch("pwd.getpwnam")
    @patch("grp.getgrnam")
    def test_are_all_tls_resources_stored(self, grp_getgrnam, pwd_getpwnam, os_chown):
        """Test if all TLS resources are successfully stored."""
        self.charm.tls.certs_path = MagicMock()

        with tempfile.TemporaryDirectory() as tmp_dir:
            self.charm.tls.certs_path = tmp_dir

            self.assertFalse(self.charm.tls.all_tls_resources_stored())

            ca_resources = create_x509_resources()

            self.charm.tls.store_new_tls_resources(
                CertType.UNIT_TRANSPORT,
                {
                    "ca-cert": "ca",
                    "cert": ca_resources.cert,
                    "key": ca_resources.key,
                },
            )
            self.assertFalse(self.charm.tls.all_tls_resources_stored())

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
            self.assertFalse(self.charm.tls.all_tls_resources_stored())

            http_resources = create_x509_resources()

            self.charm.tls.store_new_tls_resources(
                CertType.UNIT_HTTP,
                {
                    "ca-cert": "ca",
                    "cert": http_resources.cert,
                    "key": http_resources.key,
                },
            )
            self.assertTrue(self.charm.tls.all_tls_resources_stored())
