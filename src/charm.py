#!/usr/bin/env python3

# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""
import logging
from typing import List, Optional

from charms.opensearch.v0.helpers.charms import Scope
from charms.opensearch.v0.helpers.cluster import ClusterTopology, Node
from charms.opensearch.v0.helpers.networking import units_ips
from charms.opensearch.v0.helpers.security import generate_hashed_password
from charms.opensearch.v0.opensearch_base_charm import PEER, OpenSearchBaseCharm
from charms.opensearch.v0.opensearch_distro import (
    OpenSearchHttpError,
    OpenSearchInstallError,
)
from charms.opensearch.v0.opensearch_tls import CertType
from ops.charm import ActionEvent, InstallEvent, LeaderElectedEvent, RelationJoinedEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

from opensearch import OpenSearchSnap

logger = logging.getLogger(__name__)


class OpenSearchOperatorCharm(OpenSearchBaseCharm):
    """This class represents the machine charm for OpenSearch."""

    def __init__(self, *args):
        super().__init__(*args)

        self.opensearch = OpenSearchSnap(self, PEER)

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.leader_elected, self._on_leader_elected)

        self.framework.observe(self.on[PEER].relation_joined, self._on_relation_joined)

        self.framework.observe(self.on.put_client_action, self._on_put_client)
        self.framework.observe(self.on.delete_client_action, self._on_delete_client)

    def _on_install(self, event: InstallEvent) -> None:
        """Handle the install event."""
        self.unit.status = MaintenanceStatus("Installing OpenSearch...")
        try:
            self.opensearch.install()
        except OpenSearchInstallError:
            self.unit.status = BlockedStatus("Could not install OpenSearch.")
            event.defer()

        self.unit.status = ActiveStatus()

    def _on_leader_elected(self, _: LeaderElectedEvent):
        """Handle the install event."""
        if self.app_peers_data.get("security_index_initialised", None) is not None:
            return

        self.unit.status = MaintenanceStatus("Configuring admin and clients security...")

        self._initialize_admin_user()
        self._require_client_tls_auth()

        self.unit.status = ActiveStatus()

    def _on_relation_joined(self, event: RelationJoinedEvent):
        """Triggered when a new peer relation is established. Set the right node role."""
        units_ips_map = units_ips(self, PEER)
        host: Optional[str] = None
        if len(units_ips_map) > 0:
            host = next(iter(units_ips_map.values()))  # get first value

        nodes: List[Node] = []
        try:
            if host is not None:
                response = self.opensearch.request("GET", "/_nodes", host=host)
                if "nodes" in response:
                    for obj in response["nodes"].values():
                        nodes.append(Node(obj["name"], obj["roles"], obj["ip"]))
        except OpenSearchHttpError:
            event.defer()
            return

        is_cluster_bootstrapped = ClusterTopology.is_cluster_bootstrapped(nodes)

        self._initialize_node(nodes)
        self.opensearch.start()

        roles_count_map = ClusterTopology.nodes_count_by_role(nodes)
        if (
            not is_cluster_bootstrapped and roles_count_map.get("cluster_manager", 0) == 2
        ):  # we just added a CM node
            # cluster is bootstrapped now, we need to clean up the conf
            # https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-discovery-bootstrap-cluster.html
            self.opensearch.config.delete(
                "opensearch.yml", "cluster.initial_cluster_manager_nodes"
            )

    def _on_put_client(self, event: ActionEvent):
        """Create or update client / user and link the required roles to it."""
        if not self.unit.is_leader():
            return

        client_name = event.params.get("name")
        client_roles = [role.strip() for role in event.params.get("roles").split(",")]
        client_password = event.params.get("password")

        client_hosts = event.params.get("hosts", None)
        if client_hosts is not None:
            client_hosts = [host.strip() for host in client_hosts.split(",")]

        with_cert = event.params.get("with-cert", False)

        try:
            self._add_update_client(
                client_name, client_roles, client_password, client_hosts, with_cert
            )
        except OpenSearchHttpError:
            event.defer()

    def _on_delete_client(self, event: ActionEvent):
        """Delete a registered client if exists."""
        if not self.unit.is_leader():
            return

        client_name = event.params.get("name")
        try:
            resp = self.opensearch.request(
                "DELETE", f"/_plugins/_security/api/internalusers/{client_name}/"
            )
            logger.debug(resp)
        except OpenSearchHttpError:
            event.defer()

    def on_tls_conf_set(
        self, scope: Scope, cert_type: CertType, secret_key_prefix: str, renewal: bool
    ):
        """Called after certificate ready and stored on the corresponding scope databag.

        - Store the cert on the file system, on all nodes for APP certificates
        - Update the corresponding yaml conf files
        - check databag if needed to rebuild security index ? or should only be called here
        - pass admin password
        """
        current_secrets = self.secrets.get_object(scope, str(cert_type.value))

        cert = current_secrets[f"{secret_key_prefix}.cert"]
        subject = current_secrets[f"{secret_key_prefix}.subject"]
        key = current_secrets[f"{secret_key_prefix}.key"]
        key_pwd = current_secrets.get(f"{secret_key_prefix}.key-password", None)

        # Store the certificate and key on disk
        path_prefix = f"{self.opensearch.paths.certs}/{secret_key_prefix}"
        self.opensearch.write_file(f"{path_prefix}.key", key)
        self.opensearch.write_file(f"{path_prefix}.cert", cert)

        if scope == Scope.UNIT:
            self._write_node_tls_conf(cert_type, subject, key_pwd, path_prefix)
            return

        # admin cert
        self._write_admin_tls_conf(subject)
        if not self.unit.is_leader():
            return

        if self.app_peers_data.get("security_index_initialised", None) is None:
            self._initialize_security_index(key_pwd)

        self.app_peers_data["security_index_initialised"] = "True"

        # TODO: if renewal, how to handle? (can we not run the security admin script)

    def on_tls_conf_remove(self):
        """Called after certificates removed."""
        # TODO: remove from disk? remove YAML configs?
        pass

    def _initialize_node(self, nodes: List[Node]) -> None:
        """Set base config for each node in the cluster."""
        target_conf_file = "opensearch.yml"

        self.opensearch.config.put(
            target_conf_file, "cluster.name", self.config.get("cluster-name")
        )
        self.opensearch.config.put(target_conf_file, "node.name", self.unit.name)
        self.opensearch.config.put(target_conf_file, "network.host", self.opensearch.host)

        roles = ClusterTopology.suggest_roles(nodes)
        self.opensearch.config.put(target_conf_file, "node.roles", roles)

        cm_ips = ClusterTopology.get_cluster_managers_ips(nodes)
        if len(cm_ips) > 0:
            self.opensearch.config.put(target_conf_file, "discovery.seed_hosts", cm_ips)

        if "cluster_manager" in roles and len(cm_ips) < 2:  # cluster NOT bootstrapped yet
            cm_names = ClusterTopology.get_cluster_managers_names(nodes)
            cm_names.append(self.unit.name)
            self.opensearch.config.put(
                target_conf_file, "cluster.initial_cluster_manager_nodes", cm_names
            )

        self.opensearch.config.put(target_conf_file, "path.data", self.opensearch.paths.data)
        self.opensearch.config.put(target_conf_file, "path.logs", self.opensearch.paths.logs)
        self.opensearch.config.put(target_conf_file, "plugins.security.disabled", "false")

    def _initialize_admin_user(self):
        """Change default password of Admin user."""
        hashed_pwd, pwd = generate_hashed_password()
        self.secrets.put(Scope.APP, "admin_password", pwd)

        config_path = f"{self.opensearch.paths.plugins}/config/internal_users.yml"
        self.opensearch.config.put(
            config_path,
            "admin",
            {
                "hash": hashed_pwd,
                "reserved": "true",  # this protects this resource from being updated on the dashboard or rest api
                "opendistro_security_roles": ["admin"],
                "description": "Admin user",
            },
        )

    def _require_client_tls_auth(self):
        """Configure TLS and basic http for clients."""
        # The security plugin will accept TLS client certs if certs but doesn't require them
        self.opensearch.config.put(
            "opensearch.yml", "plugins.security.ssl.http.clientauth_mode", "OPTIONAL"
        )

        self.opensearch.config.put(
            f"{self.opensearch.paths.conf}/opensearch-security/config.yml",
            "config/dynamic/authc/basic_internal_auth_domain/http_enabled",
            "true"
        )

        self.opensearch.config.put(
            f"{self.opensearch.paths.conf}/opensearch-security/config.yml",
            "config/dynamic/authc/clientcert_auth_domain/http_enabled",
            "true",
        )

        self.opensearch.config.put(
            f"{self.opensearch.paths.conf}/opensearch-security/config.yml",
            "config/dynamic/authc/clientcert_auth_domain/transport_enabled",
            "true",
        )

    def _initialize_security_index(self, admin_key_password: Optional[str]):
        """Run the security_admin script, it creates and initializes the opendistro_security index.

        IMPORTANT: must only run once per cluster, otherwise the index gets overrode
        """
        args = [
            f"-cd {self.opensearch.paths.conf}/opensearch-security/",
            "-icl",
            "-nhnv",
            f"-cacert {self.opensearch.paths.certs}/root-ca.pem",
            f"-cert {self.opensearch.paths.certs}/admin.pem",
            f"-key {self.opensearch.paths.certs}/admin-key.pem",
        ]

        if admin_key_password is not None:
            args.append(f"keypass {admin_key_password}")

        self.opensearch.run_script(
            "plugins/opensearch-security/tools/securityadmin.sh", " ".join(args)
        )

    def _add_update_client(
        self,
        client_name: str,
        client_roles: List[str],
        client_password: str,
        client_hosts: Optional[List[str]],
        with_cert: bool,
    ) -> None:
        """Create or update user and assign the requested roles to the user."""
        put_user_resp = self.opensearch.request(
            "PUT",
            f"/_plugins/_security/api/internalusers/{client_name}",
            {
                "password": client_password,
                "opendistro_security_roles": client_roles,
            },
        )
        logger.debug(put_user_resp)

        if with_cert:
            payload = {
                "users": [client_name],
                "opendistro_security_roles": client_roles,
            }
            if client_hosts is not None:
                payload["hosts"] = client_hosts

            put_role_mapping_resp = self.opensearch.request(
                "PUT",
                "/_plugins/_security/api/rolesmapping/",
                payload,
            )

            logger.debug(put_role_mapping_resp)

    def _write_admin_tls_conf(self, subject: str):
        """Configures the admin certificate."""
        target_conf_file = "opensearch.yml"

        # later when CN != subject, make sure to format the subject as per RFC2253 (inverted)
        self.opensearch.config.put(
            target_conf_file, "plugins.security.authcz.admin_dn/[]", subject
        )

    def _write_node_tls_conf(
        self, cert_type: CertType, subject: str, key_pwd: Optional[str], path_prefix: str
    ):
        """Configures TLS for nodes."""
        target_conf_file = "opensearch.yml"
        target_conf_layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"

        self.opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemcert_filepath",
            f"{path_prefix}.cert",
        )

        self.opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemkey_filepath",
            f"{path_prefix}.key",
        )

        if key_pwd is not None:
            self.opensearch.config.put(
                target_conf_file,
                f"plugins.security.ssl.{target_conf_layer}.pemkey_password",
                key_pwd,
            )

        # later when CN != subject make sure to format the subject as per RFC2253 (inverted)
        self.opensearch.config.put(target_conf_file, "plugins.security.nodes_dn/[]", subject)


if __name__ == "__main__":
    main(OpenSearchOperatorCharm)
