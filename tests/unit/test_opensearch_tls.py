# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import socket
import unittest
from unittest.mock import Mock, patch

import ops
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.opensearch_base_charm import PEER
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import patch_network_get

ops.testing.SIMULATE_CAN_CONNECT = True


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
