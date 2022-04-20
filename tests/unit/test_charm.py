# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest
from pathlib import Path
from subprocess import CalledProcessError
from unittest.mock import PropertyMock, call, patch

import requests
from ops.model import BlockedStatus
from ops.testing import Harness

import charm
from charm import OpenSearchCharm
from tests.unit.helpers import patch_network_get

RESOURCES = ["tls_ca", "tls_key", "admin_key", "admin_cert", "open_ssl_conf"]


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(OpenSearchCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.peer_rel_id = self.harness.add_relation(charm.PEER, "opensearch")
        self.client_rel_id = self.harness.add_relation("client", "graylog")

    def get_dn(self, name):
        return f"CN={name},OU=Data Plataform,O=Canonical,L=TORONTO,ST=ONTARIO,C=CA"

    @patch_network_get()
    @patch("charm.socket")
    @patch("charm.service_restart")
    @patch("charm.daemon_reload")
    @patch("charm.OpenSearchCharm._configure_security")
    @patch("charm.OpenSearchCharm._write_config")
    @patch("charm.check_call")
    def test_on_config_changed(
        self,
        mock_call,
        mock_write_config,
        configure_security,
        mock_daemon,
        mock_restart,
        mock_socket,
    ):
        with patch("charm.OpenSearchCharm._node_dn", new_callable=PropertyMock) as node_dn:
            with patch("charm.OpenSearchCharm._admin_dn", new_callable=PropertyMock) as admin_dn:
                node_dn.return_value = self.get_dn("opensearch-0")
                admin_dn.return_value = self.get_dn("ADMIN")
                self.harness.add_relation_unit(self.client_rel_id, "graylog/0")
                with self.assertLogs("charm", "INFO") as logger:
                    with patch(
                        "charm.OpenSearchCharm._master_node", new_callable=PropertyMock
                    ) as master_node:
                        master_node.return_value = ["opensearch-0"]
                        mock_socket.getfqdn.return_value = "opensearch-0"
                        mock_socket.gethostname.return_value = "opensearch-0"
                        self.harness.update_config({"cluster_name": "foo_cluster"})

                        expected_context = {
                            "cluster_name": "foo_cluster",
                            "os_java_opts": 1,
                            "max_map_count": 262144,
                            "unit_ips": ["10.6.215.1"],
                            "network_host": "10.6.215.1",
                            "node_name": "opensearch-0",
                            "host_name": "opensearch-0",
                            "node_cert": "opensearch-0.pem",
                            "node_key": "opensearch-0-key.pem",
                            "admin_dn": self.get_dn("ADMIN"),
                            "ca": "root-ca.pem",
                            "nodes_dn": [self.get_dn("opensearch-0")],
                            "master_node": ["opensearch-0"],
                            "followers_dn": [],
                        }
                        for template in charm.CONFIG_MAP:
                            cmd = charm.CONFIG_MAP[template].get("cmd")
                            if cmd:
                                expected_check_call = call(cmd.split())
                                self.assertIn(expected_check_call, mock_call.call_args_list)
                            config_path = charm.CONFIG_MAP[template].get("config_path")
                            chmod = charm.CONFIG_MAP[template].get("chmod")
                            expected_write_call = call(
                                config_path, template, expected_context, chmod
                            )
                            self.assertIn(expected_write_call, mock_write_config.call_args_list)

                        # change cluster name and check if relation changed
                        self.assertEqual(
                            self.harness.get_relation_data(self.client_rel_id, "opensearch/0"),
                            {"cluster_name": "foo_cluster", "port": "9200"},
                        )
                        self.assertIn("Updating client relation data", "".join(logger.output))
                        mock_daemon.assert_called_once()
                        mock_restart.assert_called_once_with("snap.opensearch.daemon.service")

    @patch_network_get()
    @patch("charm.OpenSearchCharm._configure_security")
    @patch(
        "charm.CONFIG_MAP",
        {"bar_template": {"cmd": "foo_cmd", "config_path": "/etc/", "chmod": 0o644}},
    )
    @patch("charm.OpenSearchCharm._write_config")
    @patch("charm.check_call")
    def test_on_config_changed_error(self, mock_call, mock_write_config, _configure_security):
        mock_call.side_effect = CalledProcessError(1, "foo_cmd", "foo cmd error")
        with self.assertLogs("charm", "ERROR") as logger:
            with self.assertRaises(CalledProcessError):
                self.harness.charm.on.config_changed.emit()
        self.assertIn("Failed to run command foo_cmd", "".join(logger.output))

    @patch_network_get()
    @patch("charm.socket")
    @patch("charm.service_restart")
    @patch("charm.daemon_reload")
    @patch("charm.OpenSearchCharm._configure_security")
    @patch("charm.OpenSearchCharm._write_config")
    def test_opensearch_relation(
        self, mock_write, mock_security, mock_daemon, mock_restart, mock_socket
    ):
        with patch("charm.OpenSearchCharm._node_dn", new_callable=PropertyMock) as node_dn:
            with patch("charm.OpenSearchCharm._admin_dn", new_callable=PropertyMock) as admin_dn:
                with patch(
                    "charm.OpenSearchCharm._master_node", new_callable=PropertyMock
                ) as master_node:
                    master_node.return_value = ["opensearch-0"]
                    node_dn.return_value = self.get_dn("opensearch-0")
                    admin_dn.return_value = self.get_dn("ADMIN")
                    mock_socket.getfqdn.return_value = "opensearch-0"
                    mock_socket.gethostname.return_value = "opensearch-0"
                    expected_context = {
                        "cluster_name": "opensearch",
                        "os_java_opts": 1,
                        "max_map_count": 262144,
                        "unit_ips": ["10.6.215.2", "10.6.215.1"],
                        "network_host": "10.6.215.1",
                        "node_name": "opensearch-0",
                        "host_name": "opensearch-0",
                        "node_cert": "opensearch-0.pem",
                        "node_key": "opensearch-0-key.pem",
                        "admin_dn": self.get_dn("ADMIN"),
                        "ca": "root-ca.pem",
                        "nodes_dn": [self.get_dn("opensearch-0"), self.get_dn("opensearch-1")],
                        "master_node": ["opensearch-0"],
                        "followers_dn": [],
                    }
                    self.harness.add_relation_unit(self.peer_rel_id, "opensearch/1")
                    self.harness.update_relation_data(
                        self.peer_rel_id,
                        "opensearch/1",
                        {"private-address": "10.6.215.2", "dn": self.get_dn("opensearch-1")},
                    )
                    expected_call = call(
                        charm.CONFIG_PATH, "opensearch.yml", expected_context, 0o660
                    )
                    # check that opensearch relation changed was called
                    self.assertIn(expected_call, mock_write.call_args_list)

                    resulting_ips = self.harness.charm._unit_ips
                    expected_ips = ["10.6.215.2", "10.6.215.1"]
                    self.assertEqual(resulting_ips, expected_ips)
                    mock_daemon.assert_called_once()
                    mock_restart.assert_called_once_with("snap.opensearch.daemon.service")

    def test_client_relation_joined(self):
        relation_parameters = {"cluster_name": "opensearch", "port": "9200"}
        self.harness.add_relation_unit(self.client_rel_id, "graylog/0")
        self.assertEqual(
            self.harness.get_relation_data(self.client_rel_id, "opensearch/0"), relation_parameters
        )

    def test_client_relation_changed(self):
        relation_parameters = {"cluster_name": "foo_cluster", "port": "9200"}
        self.harness.add_relation_unit(self.client_rel_id, "graylog/0")
        self.harness.update_relation_data(self.client_rel_id, "opensearch/0", relation_parameters)
        self.assertEqual(
            self.harness.get_relation_data(self.client_rel_id, "opensearch/0"), relation_parameters
        )

    @patch("charm.check_output")
    def test_get_dn(self, mock_check_output):
        cert_path = Path("/tmp")
        mock_check_output.return_value = (
            "subject=CN=opensearch-0,OU=Data Plataform,O=Canonical,L=TORONTO,ST=ONTARIO,C=CA\n"
        ).encode("ascii")
        expected_dn = self.get_dn("opensearch-0")
        with self.assertLogs("charm", "INFO") as logger:
            dn = self.harness.charm._get_dn(cert_path)
            self.assertEqual(dn, expected_dn)
        self.assertIn(f"Getting DN from file {cert_path}", "".join(logger.output))

    @patch("charm.check_output")
    def test_get_dn_error(self, mock_check_output):
        cert_path = Path("/tmp")
        mock_check_output.side_effect = CalledProcessError(1, "openssl x509 foo")
        with self.assertLogs("charm", "ERROR") as logger:
            with self.assertRaises(CalledProcessError):
                self.harness.charm._get_dn(cert_path)
        self.assertIn("Failed to run command openssl x509 foo", "".join(logger.output))

    @patch("charm.OpenSearchCharm._configure_self_signed_cert")
    def test_configure_security_self_signed(self, mock_self_signed):
        self.harness.charm._configure_security()
        mock_self_signed.assert_called_once()

    @patch("charm.OpenSearchCharm._configure_self_signed_cert")
    def test_configure_security_ca_signed(self, mock_self_signed):
        certificates_rel_id = self.harness.add_relation("certificates", "vault")
        self.harness.add_relation_unit(certificates_rel_id, "vault/0")
        self.harness.charm._configure_security()
        mock_self_signed.assert_not_called()

    @patch.object(charm.Path, "exists")
    def test_configure_self_signed_cert_exists(self, mock_exists):
        mock_exists.return_value = True
        with self.assertLogs("charm", "INFO") as logger:
            self.harness.charm._configure_self_signed_cert()
        self.assertIn(
            "Private key and cert already created on opensearch/0", "".join(logger.output)
        )

    @patch("charm.check_call")
    def test_configure_self_signed_cert_not_exists_empty(self, mock_exists):
        mock_exists.return_value = False
        expected_msg = (
            "File root-ca.pem is empty. " "Check README on how to create self-signed certificates"
        )
        for resource in RESOURCES:
            # add tls_ca file as an empty resource
            if resource == RESOURCES[0]:
                self.harness.add_resource(resource, "")
            else:
                self.harness.add_resource(resource, "cert content or openssl config")
        with self.assertLogs("charm", "WARNING") as logger:
            with self.assertRaises(ResourceWarning):
                self.harness.charm._configure_self_signed_cert()
        self.assertIn(
            "Check README on how to create self-signed certificates", "".join(logger.output)
        )
        # ensure unit is blocked
        self.assertEqual(self.harness.model.unit.status, BlockedStatus(expected_msg))

    @patch("charm.grp.getgrnam")
    @patch("charm.pwd.getpwnam")
    @patch("charm.OpenSearchCharm._run_security_plugin")
    @patch("charm.os.chown")
    @patch("charm.check_call")
    @patch("charm.OpenSearchCharm._write_config")
    @patch("charm.OpenSearchCharm._get_context")
    @patch.object(charm.Path, "unlink")
    @patch.object(charm.Path, "write_text")
    @patch.object(charm.Path, "exists")
    def test_configure_self_signed_cert_not_exists(
        self,
        mock_exists,
        mock_write_text,
        mock_unlink,
        mock_context,
        mock_write_config,
        mock_check_call,
        mock_chown,
        mock_security_plugin,
        mock_pwd,
        mock_grp,
    ):
        mock_exists.return_value = False
        for resource in RESOURCES:
            self.harness.add_resource(resource, "cert content or openssl config")
        with self.assertLogs("charm", "INFO") as logger:
            self.harness.charm._configure_self_signed_cert()
            # assert that calls check_call to generate private key and cert
            self.assertTrue(len(mock_check_call.call_args_list) == 4)
            # assert that writes resources in the config folder
            self.assertTrue(len(mock_write_text.call_args_list) == len(RESOURCES))
            # assert that erases two files (tmp key and csr)
            self.assertTrue(len(mock_unlink.call_args_list) == 2)
            mock_write_config.assert_called_once()
            mock_context.assert_called_once()
            mock_chown.assert_called()
            mock_security_plugin.assert_called_once()
            mock_pwd.assert_called_with("snap_daemon")
            mock_grp.assert_called_with("snap_daemon")
        self.assertIn("Creating private key and cert for opensearch/0", "".join(logger.output))

    @patch("charm.grp.getgrnam")
    @patch("charm.pwd.getpwnam")
    @patch("charm.os.chown")
    @patch("charm.check_call")
    @patch("charm.OpenSearchCharm._write_config")
    @patch("charm.OpenSearchCharm._get_context")
    @patch.object(charm.Path, "write_text")
    @patch.object(charm.Path, "exists")
    def test_configure_self_signed_cert_fail_called_pe(
        self,
        mock_exists,
        mock_write_text,
        mock_context,
        mock_write_config,
        mock_check_call,
        mock_chown,
        mock_pwd,
        mock_grp,
    ):
        for resource in RESOURCES:
            self.harness.add_resource(resource, "cert content or openssl config")
        mock_exists.return_value = False
        with self.assertLogs("charm", "ERROR") as logger:
            with self.assertRaises(CalledProcessError):
                mock_check_call.side_effect = CalledProcessError(1, "openssl foo")
                self.harness.charm._configure_self_signed_cert()
        self.assertIn("Failed to run command openssl foo", "".join(logger.output))

    @patch("charm.grp.getgrnam")
    @patch("charm.pwd.getpwnam")
    @patch("charm.os.chown")
    @patch("charm.check_call")
    @patch("charm.OpenSearchCharm._write_config")
    @patch("charm.OpenSearchCharm._get_context")
    @patch.object(charm.Path, "write_text")
    @patch.object(charm.Path, "exists")
    def test_configure_self_signed_cert_fail_file(
        self,
        mock_exists,
        mock_write_text,
        mock_context,
        mock_write_config,
        mock_check_call,
        mock_chown,
        mock_pwd,
        mock_grp,
    ):
        for resource in RESOURCES:
            self.harness.add_resource(resource, "cert content or openssl config")
        mock_exists.return_value = False
        with self.assertLogs("charm", "ERROR") as logger:
            with self.assertRaises(FileNotFoundError):
                mock_check_call.side_effect = FileNotFoundError
                self.harness.charm._configure_self_signed_cert()
        self.assertIn("FileNotFoundError:", "".join(logger.output))

    @patch("charm.OpenSearchCharm._on_config_changed")
    def test_ccr_leader_relation(self, mock_config_changed):
        ccr_leader_id = self.harness.add_relation("ccr_leader", "opensearch-follower")
        self.harness.add_relation_unit(ccr_leader_id, "opensearch-follower/0")
        # assert on_config_changed is called on leader cluster to add
        # followers_dn
        mock_config_changed.assert_called()

    @patch("charm.requests")
    def test_ccr_follower_relation_leader(self, mock_requests):
        expected_put = call.put(
            "https://localhost:9200/_cluster/settings?pretty",
            json={
                "persistent": {
                    "cluster": {"remote": {charm.CCR_CONNECTION: {"seeds": ["10.6.215.2:9300"]}}}
                }
            },
            cert=self.harness.charm._admin_cert_requests,
            verify=self.harness.charm._ca_cert,
        )
        expected_post = call.post(
            "https://localhost:9200/_plugins/_replication/_autofollow?pretty",
            json={
                "leader_alias": charm.CCR_CONNECTION,
                "name": "all-replication-rule",
                "pattern": "*",
                "use_roles": {
                    "leader_cluster_role": "all_access",
                    "follower_cluster_role": "all_access",
                },
            },
            cert=self.harness.charm._admin_cert_requests,
            verify=self.harness.charm._ca_cert,
        )

        with patch("charm.OpenSearchCharm._node_dn", new_callable=PropertyMock) as node_dn:
            self.harness.set_leader(True)
            node_dn.return_value = self.get_dn("opensearch-follower-0")
            ccr_follower_id = self.harness.add_relation("ccr_follower", "opensearch-leader")
            self.harness.add_relation_unit(ccr_follower_id, "opensearch-leader/0")
            self.harness.update_relation_data(
                ccr_follower_id, "opensearch-leader/0", {"private-address": "10.6.215.2"}
            )
            # check that DN was passed to the leader unit
            self.assertDictEqual(
                self.harness.get_relation_data(ccr_follower_id, "opensearch/0"),
                {"dn": self.get_dn("opensearch-follower-0")},
            )
            request_calls = mock_requests.method_calls
            self.assertTrue(len(request_calls) == 2)
            self.assertIn(expected_put, request_calls)
            self.assertIn(expected_post, request_calls)

    @patch("charm.requests")
    def test_ccr_follower_relation_leader_put_error(self, mock_requests):
        with patch("charm.OpenSearchCharm._node_dn", new_callable=PropertyMock) as node_dn:
            self.harness.set_leader(True)
            response = requests.Response()
            response.status_code = 400
            mock_requests.put.return_value = response
            with self.assertLogs("charm", "ERROR") as logger:
                with self.assertRaises(requests.exceptions.HTTPError):
                    node_dn.return_value = self.get_dn("opensearch-follower-0")
                    ccr_follower_id = self.harness.add_relation(
                        "ccr_follower", "opensearch-leader"
                    )
                    self.harness.add_relation_unit(ccr_follower_id, "opensearch-leader/0")
                    self.harness.update_relation_data(
                        ccr_follower_id, "opensearch-leader/0", {"private-address": "10.6.215.2"}
                    )
            self.assertIn("Failed to create a CCR connection:", "".join(logger.output))

    @patch("charm.requests")
    def test_ccr_follower_relation_leader_post_error(self, mock_requests):
        with patch("charm.OpenSearchCharm._node_dn", new_callable=PropertyMock) as node_dn:
            self.harness.set_leader(True)
            response = requests.Response()
            response.status_code = 400
            mock_requests.post.return_value = response
            with self.assertLogs("charm", "ERROR") as logger:
                with self.assertRaises(requests.exceptions.HTTPError):
                    node_dn.return_value = self.get_dn("opensearch-follower-0")
                    ccr_follower_id = self.harness.add_relation(
                        "ccr_follower", "opensearch-leader"
                    )
                    self.harness.add_relation_unit(ccr_follower_id, "opensearch-leader/0")
                    self.harness.update_relation_data(
                        ccr_follower_id, "opensearch-leader/0", {"private-address": "10.6.215.2"}
                    )
            self.assertIn("Failed to create a CCR auto-follow:", "".join(logger.output))

    @patch("charm.requests")
    def test_ccr_follower_relation_leader_put_defer(self, mock_requests):
        with patch("charm.OpenSearchCharm._node_dn", new_callable=PropertyMock) as node_dn:
            self.harness.set_leader(True)
            mock_requests.put.side_effect = OSError
            with self.assertLogs("charm", "DEBUG") as logger:
                node_dn.return_value = self.get_dn("opensearch-follower-0")
                ccr_follower_id = self.harness.add_relation("ccr_follower", "opensearch-leader")
                self.harness.add_relation_unit(ccr_follower_id, "opensearch-leader/0")
                self.harness.update_relation_data(
                    ccr_follower_id, "opensearch-leader/0", {"private-address": "10.6.215.2"}
                )
            self.assertIn("CCR not ready yet with socket error:", "".join(logger.output))

    @patch("charm.requests")
    def test_ccr_follower_relation_leader_post_defer(self, mock_requests):
        with patch("charm.OpenSearchCharm._node_dn", new_callable=PropertyMock) as node_dn:
            self.harness.set_leader(True)
            response = requests.Response()
            response.status_code = 500
            mock_requests.post.return_value = response
            with self.assertLogs("charm", "DEBUG") as logger:
                node_dn.return_value = self.get_dn("opensearch-follower-0")
                ccr_follower_id = self.harness.add_relation("ccr_follower", "opensearch-leader")
                self.harness.add_relation_unit(ccr_follower_id, "opensearch-leader/0")
                self.harness.update_relation_data(
                    ccr_follower_id, "opensearch-leader/0", {"private-address": "10.6.215.2"}
                )
            self.assertIn("CCR not ready yet:", "".join(logger.output))

    @patch("charm.requests")
    def test_ccr_follower_relation_not_leader(self, mock_requests):
        with patch("charm.OpenSearchCharm._node_dn", new_callable=PropertyMock) as node_dn:
            self.harness.set_leader(False)
            node_dn.return_value = self.get_dn("opensearch-follower-0")
            ccr_follower_id = self.harness.add_relation("ccr_follower", "opensearch")
            self.harness.add_relation_unit(ccr_follower_id, "opensearch-leader/0")
            mock_requests.put.assert_not_called()
            mock_requests.post.assert_not_called()
