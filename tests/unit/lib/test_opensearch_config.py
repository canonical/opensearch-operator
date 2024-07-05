# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import shutil
import unittest
from typing import Dict
from unittest.mock import Mock

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.models import App
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import copy_file_content_to_tmp


class TestOpenSearchConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)

        self.config_path = "tests/unit/resources/config"
        self.opensearch_yml = copy_file_content_to_tmp(self.config_path, "opensearch.yml")
        self.seed_unicast_hosts = copy_file_content_to_tmp(self.config_path, "unicast_hosts.txt")
        self.jvm_options = copy_file_content_to_tmp(self.config_path, "jvm.options")
        self.sec_conf_yml = copy_file_content_to_tmp(
            self.config_path, "opensearch-security/config.yml"
        )

        self.charm.opensearch = Mock()
        self.charm.opensearch.network_hosts = ["10.10.10.10"]
        self.charm.opensearch.host = "20.20.20.20"

        self.charm.opensearch.paths = Mock()
        self.charm.opensearch.paths.conf = None
        self.charm.opensearch.paths.seed_hosts = self.seed_unicast_hosts
        self.charm.opensearch.paths.certs_relative = "certificates"
        self.charm.opensearch.paths.data = "data"
        self.charm.opensearch.paths.logs = "logs"
        self.charm.opensearch.config = YamlConfigSetter(f"{self.config_path}/tmp")

        self.opensearch_config = self.charm.opensearch_config
        self.opensearch_config._opensearch = self.charm.opensearch

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
        self.opensearch_config.set_node_tls_conf(
            CertType.UNIT_TRANSPORT, truststore_pwd="123", keystore_pwd="987"
        )
        self.opensearch_config.set_node_tls_conf(
            CertType.UNIT_HTTP, truststore_pwd="123", keystore_pwd="987"
        )

        # check the changes
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)

        for layer in ["http", "transport"]:
            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.keystore_type"],
                "PKCS12",
            )
            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.truststore_type"],
                "PKCS12",
            )

            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.keystore_filepath"],
                f"certificates/unit-{layer}.p12",
            )
            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.truststore_filepath"],
                "certificates/ca.p12",
            )

            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.keystore_alias"],
                f"unit-{layer}",
            )
            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.truststore_alias"],
                "ca",
            )

            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.keystore_password"],
                "987",
            )
            self.assertEqual(
                opensearch_conf[f"plugins.security.ssl.{layer}.truststore_password"],
                "123",
            )

    def test_append_transport_node(self):
        """Test setting the transport config of node."""
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        self.assertNotIn("plugins.security.nodes_dn", opensearch_conf)
        self.opensearch_config.append_transport_node(["10.10.10.10"])

        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        self.assertCountEqual(opensearch_conf["plugins.security.nodes_dn"], ["10.10.10.10"])

    def test_set_node_and_cleanup_if_bootstrapped(self):
        """Test setting the core config of a node."""
        app = App(model_uuid=self.charm.model.uuid, name=self.charm.app.name)
        self.opensearch_config.set_node(
            app=app,
            cluster_name="opensearch-dev",
            unit_name=self.charm.unit_name,
            roles=["cluster_manager", "data"],
            cm_names=["cm1"],
            cm_ips=["20.20.20.20"],
            contribute_to_bootstrap=True,
            node_temperature="hot",
        )
        opensearch_conf = self.yaml_conf_setter.load(self.opensearch_yml)
        self.assertEqual(opensearch_conf["cluster.name"], "opensearch-dev")
        self.assertEqual(opensearch_conf["node.name"], self.charm.unit_name)
        self.assertEqual(opensearch_conf["node.attr.temp"], "hot")
        self.assertEqual(opensearch_conf["node.attr.app_id"], app.id)
        self.assertEqual(opensearch_conf["network.host"], ["_site_", "10.10.10.10"])
        self.assertEqual(opensearch_conf["network.publish_host"], "20.20.20.20")
        self.assertEqual(opensearch_conf["node.roles"], ["cluster_manager", "data"])
        self.assertEqual(opensearch_conf["discovery.seed_providers"], "file")
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

        # test unicast_hosts content
        with open(self.seed_unicast_hosts, "r") as f:
            stored = set([line.strip() for line in f.readlines()])
            expected = {"20.20.20.20"}
            self.assertEqual(stored, expected)

    def tearDown(self) -> None:
        shutil.rmtree(f"{self.config_path}/tmp")
