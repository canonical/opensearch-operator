# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import socket
import unittest
from unittest.mock import Mock, patch

import ops
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.opensearch_base_charm import PEER
from ops.testing import Harness
from tests.helpers import patch_network_get, copy_file_content_to_tmp

from charm import OpenSearchOperatorCharm

ops.testing.SIMULATE_CAN_CONNECT = True


@patch_network_get("1.1.1.1")
class TestOpenSearchTLS(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _create_directories) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PEER, self.charm.app.name)

        config_path = "tests/unit/resources/config"
        self.sec_conf_yml = copy_file_content_to_tmp(
            config_path, "opensearch-security/internal_users.yml"
        )

        self.charm.opensearch = Mock()
        self.charm.opensearch.network_hosts = ["10.10.10.10"]
        self.charm.opensearch.paths.conf = None
        self.charm.opensearch.config = YamlConfigSetter(f"{config_path}/tmp")

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
