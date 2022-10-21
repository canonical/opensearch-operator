# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import socket
import unittest
from unittest.mock import Mock, patch

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.opensearch_base_charm import PEER
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import patch_network_get


@patch_network_get("1.1.1.1")
class TestOpenSearchTLS(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    @patch("charm.OpenSearchOperatorCharm._initialize_admin_user")
    def setUp(self, _create_directories, _initialize_admin_user) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PEER, self.charm.app.name)

        self.harness.set_leader(True)

        self.secret_store = self.charm.secrets

        socket.getfqdn = Mock()
        socket.getfqdn.return_value = "nebula"

    def test_get_sans(self):
        """Test the SANs returned depending on the cert type."""
        self.assertDictEqual(
            self.charm.tls._get_sans(CertType.APP_ADMIN),
            {"sans_oid": "1.2.3.4.5.5"},
        )

        for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT]:
            self.assertDictEqual(
                self.charm.tls._get_sans(cert_type),
                {
                    "sans_oid": "1.2.3.4.5.5",
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

        self.secret_store.put_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val, {"cert": event_data_cert})
        self.secret_store.put_object(Scope.APP, CertType.APP_ADMIN.val, {"csr": event_data_csr})

    def test_on_relation_joined(self):
        """Test on certificate relation joined event."""
        pass

    def test_on_set_tls_private_key(self):
        """Test _on_set_tls private key event."""
        pass