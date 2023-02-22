# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import shutil
import unittest
from typing import Dict
from unittest.mock import Mock, patch

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.opensearch_base_charm import PEER
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import copy_file_content_to_tmp


class TestOpenSearchConfig(unittest.TestCase):
    @patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution._create_directories")
    def setUp(self, _create_directories) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PEER, self.charm.app.name)

        self.config_path = "tests/unit/resources/config"
        self.opensearch_yml = copy_file_content_to_tmp(self.config_path, "opensearch.yml")
        self.jvm_options = copy_file_content_to_tmp(self.config_path, "jvm.options")
        self.sec_conf_yml = copy_file_content_to_tmp(
            self.config_path, "opensearch-security/config.yml"
        )

        self.charm.opensearch = Mock()
        self.charm.opensearch.network_hosts = ["10.10.10.10"]
        self.charm.opensearch.paths.conf = None
        self.charm.opensearch.config = YamlConfigSetter(f"{self.config_path}/tmp")

        self.opensearch_config = self.charm.opensearch_config
        self.opensearch_config._opensearch = self.charm.opensearch
        self.opensearch_config._opensearch.paths = Mock()

        self.opensearch_config._opensearch.paths.certs_relative = "certificates"
        self.opensearch_config._opensearch.paths.data = "data"
        self.opensearch_config._opensearch.paths.logs = "logs"

        self.yaml_conf_setter = YamlConfigSetter()

    def test_set_client_auth(self):
        """Test setting the client authentication config."""

        def authc() -> Dict[str, any]:
            return security_conf["config"]["dynamic"]["authc"]

        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        security_conf = self.yaml_conf_setter.load(self.sec_conf_yml)

        # check initial stage
        self.assertNotIn("plugins.security.ssl.http.clientauth_mode", opensearch_conf)
        self.assertTrue(authc()["basic_internal_auth_domain"]["http_enabled"])
        self.assertFalse(authc()["clientcert_auth_domain"]["http_enabled"])
        self.assertFalse(authc()["clientcert_auth_domain"]["transport_enabled"])

        # call method
        self.opensearch_config.set_client_auth()

        # check the changes
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        security_conf = self.yaml_conf_setter.load(self.sec_conf_yml)

        self.assertEqual(opensearch_conf["plugins.security.ssl.http.clientauth_mode"], "OPTIONAL")
        self.assertTrue(authc()["basic_internal_auth_domain"]["http_enabled"])
        self.assertTrue(authc()["clientcert_auth_domain"]["http_enabled"])
        self.assertTrue(authc()["clientcert_auth_domain"]["transport_enabled"])

    def test_set_admin_tls_conf(self):
        """Test setting the admin TLS conf."""
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)

        # check initial stage
        self.assertNotIn("plugins.security.authcz.admin_dn", opensearch_conf)

        # call
        self.opensearch_config.set_admin_tls_conf({"subject": "CN=localhost"})

        # check the changes
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        self.assertCountEqual(
            opensearch_conf["plugins.security.authcz.admin_dn"], ["CN=localhost"]
        )

    def test_set_node_tls_conf(self):
        """Test setting the TLS conf of the node."""
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)

        # check initial stage
        for layer in ["http", "transport"]:
            self.assertNotIn(f"plugins.security.ssl.{layer}.pemcert_filepath", opensearch_conf)
            self.assertNotIn(f"plugins.security.ssl.{layer}.pemkey_filepath", opensearch_conf)
            self.assertNotIn(
                f"plugins.security.ssl.{layer}.pemtrustedcas_filepath", opensearch_conf
            )
            self.assertNotIn(f"plugins.security.ssl.{layer}.pemkey_password", opensearch_conf)

        # call
        self.opensearch_config.set_node_tls_conf(CertType.UNIT_TRANSPORT, {})
        self.opensearch_config.set_node_tls_conf(CertType.UNIT_HTTP, {"key-password": "123"})

        # check the changes
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)

        for layer in ["http", "transport"]:
            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.pemcert_filepath"],
                f"certificates/unit-{layer}.cert",
            )
            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.pemkey_filepath"],
                f"certificates/unit-{layer}.key",
            )
            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.pemtrustedcas_filepath"],
                "certificates/root-ca.cert",
            )
        self.assertEqual(opensearch_conf["plugins.security.ssl.http.pemkey_password"], "123")
        self.assertNotIn("plugins.security.ssl.transport.pemkey_password", opensearch_conf)

    def test_append_transport_node(self):
        """Test setting the transport config of node."""
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        self.assertNotIn("plugins.security.nodes_dn", opensearch_conf)
        self.opensearch_config.append_transport_node(["10.10.10.10"])

        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        self.assertCountEqual(opensearch_conf["plugins.security.nodes_dn"], ["10.10.10.10"])

    def test_set_node_and_cleanup_if_bootstrapped(self):
        """Test setting the core config of a node."""
        self.opensearch_config.set_node(
            self.charm.app.name,
            self.charm.model.name,
            self.charm.unit_name,
            ["cluster_manager", "data"],
            ["cm1"],
            ["10.10.10.10"],
            True,
        )
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        self.assertEqual(
            opensearch_conf["cluster.name"], f"{self.charm.app.name}-{self.charm.model.name}"
        )
        self.assertEqual(opensearch_conf["node.name"], self.charm.unit_name)
        self.assertEqual(opensearch_conf["network.host"], ["_site_", "10.10.10.10"])
        self.assertEqual(opensearch_conf["node.roles"], ["cluster_manager", "data"])
        self.assertEqual(opensearch_conf["discovery.seed_hosts"], ["10.10.10.10"])
        self.assertEqual(opensearch_conf["cluster.initial_cluster_manager_nodes"], ["cm1"])
        self.assertEqual(opensearch_conf["path.data"], "data")
        self.assertEqual(opensearch_conf["path.logs"], "logs")
        self.assertEqual(opensearch_conf["plugins.security.disabled"], False)
        self.assertEqual(opensearch_conf["plugins.security.ssl.http.enabled"], True)
        self.assertEqual(
            opensearch_conf["plugins.security.ssl.transport.enforce_hostname_verification"], True
        )

        # test cleanup_conf_if_bootstrapped
        self.opensearch_config.cleanup_bootstrap_conf()
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        self.assertNotIn("cluster.initial_cluster_manager_nodes", opensearch_conf)

    def tearDown(self) -> None:
        shutil.rmtree(f"{self.config_path}/tmp")
