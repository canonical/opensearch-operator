# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import socket
import unittest
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

from charms.opensearch.v0.constants_tls import TLS_RELATION, CertType
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.opensearch_base_charm import PEER
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import create_utf8_encoded_private_key, patch_network_get


@patch_network_get("1.1.1.1")
class TestOpenSearchTLS(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def setUp(self, _create_directories, _initialize_admin_user) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.harness.add_relation(PEER, self.charm.app.name)
        self.harness.add_relation(TLS_RELATION, self.charm.app.name)

        self.secret_store = self.charm.secrets

        socket.getfqdn = Mock()
        socket.getfqdn.return_value = "nebula"

    def test_get_sans(self):
        """Test the SANs returned depending on the cert type."""
        self.assertDictEqual(
            self.charm.tls._get_sans(CertType.APP_ADMIN),
            {"sans_oid": ["1.2.3.4.5.5"]},
        )

        for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT]:
            self.assertDictEqual(
                self.charm.tls._get_sans(cert_type),
                {
                    "sans_oid": ["1.2.3.4.5.5"],
                    "sans_ip": ["1.1.1.1"],
                    "sans_dns": [self.charm.unit_name, "nebula"],
                },
            )

    def test_find_secret(self):
        """Test the secrets lookup depending on the event data."""
        event_data_cert = "cert_abcd12345"
        event_data_csr = "csr_abcd12345"

        self.assertIsNone(self.charm.tls._find_secret(event_data_cert, "cert"))
        self.assertIsNone(self.charm.tls._find_secret(event_data_csr, "csr"))

        self.secret_store.put_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, {"cert": event_data_cert}
        )
        self.secret_store.put_object(Scope.APP, CertType.APP_ADMIN.val, {"csr": event_data_csr})

    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def test_on_relation_joined_admin(self, _initialize_admin_user, _request_certificate):
        """Test on certificate relation joined event."""
        event_mock = MagicMock()

        self.harness.set_leader(is_leader=True)
        self.charm.tls._on_tls_relation_joined(event_mock)
        self.assertEqual(
            _request_certificate.mock_calls,
            [
                mock.call(Scope.APP, CertType.APP_ADMIN),
                mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT),
                mock.call(Scope.UNIT, CertType.UNIT_HTTP),
            ],
        )

    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def test_on_relation_joined_non_admin(self, _initialize_admin_user, _request_certificate):
        """Test on certificate relation joined event."""
        event_mock = MagicMock()

        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_tls_relation_joined(event_mock)
        self.assertEqual(
            _request_certificate.mock_calls,
            [
                mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT),
                mock.call(Scope.UNIT, CertType.UNIT_HTTP),
            ],
        )

    @patch("charm.OpenSearchOperatorCharm.on_tls_relation_broken")
    def test_on_relation_broken(self, on_tls_relation_broken):
        """Test on certificate relation broken event."""
        event_mock = MagicMock()
        self.charm.tls._on_tls_relation_broken(event_mock)

        on_tls_relation_broken.assert_called_once()

    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def test_on_set_tls_private_key(self, _initialize_admin_user, _request_certificate):
        """Test _on_set_tls private key event."""
        event_mock = MagicMock(params={"category": "app-admin"})

        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_set_tls_private_key(event_mock)
        _request_certificate.assert_not_called()

        self.harness.set_leader(is_leader=True)
        self.charm.tls._on_set_tls_private_key(event_mock)
        _request_certificate.assert_called_once()

        event_mock = MagicMock(params={"category": "unit-transport"})
        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_set_tls_private_key(event_mock)
        _request_certificate.assert_called()

    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charm.OpenSearchOperatorCharm.on_tls_conf_set")
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def test_on_certificate_available(
        self, _initialize_admin_user, on_tls_conf_set, _request_certificate
    ):
        """Test _on_certificate_available event."""
        csr = "csr_12345"
        cert = "cert_12345"
        chain = "chain_12345"
        ca = "ca_12345"
        secret_key = CertType.UNIT_TRANSPORT.val

        self.secret_store.put_object(Scope.UNIT, secret_key, {"csr": csr})

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )
        self.charm.tls._on_certificate_available(event_mock)

        self.assertDictEqual(
            self.secret_store.get_object(Scope.UNIT, secret_key),
            {"csr": csr, "chain": chain, "cert": cert, "ca": ca},
        )

        on_tls_conf_set.assert_called()

    @patch(
        "charms.tls_certificates_interface.v1.tls_certificates.TLSCertificatesRequiresV1.request_certificate_creation"
    )
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def test_on_certificate_expiring(self, _initialize_admin_user, request_certificate_creation):
        """Test _on_certificate_available event."""
        csr = "csr_12345"
        cert = "cert_12345"
        key = create_utf8_encoded_private_key()
        secret_key = CertType.UNIT_TRANSPORT.val

        self.secret_store.put_object(
            Scope.UNIT,
            secret_key,
            {"csr": csr, "cert": cert, "key": key},
        )

        event_mock = MagicMock(certificate=cert)
        self.charm.tls._on_certificate_expiring(event_mock)

        request_certificate_creation.assert_called_once()
