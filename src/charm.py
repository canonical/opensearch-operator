#!/usr/bin/env python3

# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""
import logging
from datetime import datetime
from typing import Dict, List, Optional

from charms.opensearch.v0.helpers.cluster import ClusterTopology, Node
from charms.opensearch.v0.helpers.databag import Scope
from charms.opensearch.v0.helpers.networking import units_ips
from charms.opensearch.v0.helpers.security import (
    cert_expiration_remaining_hours,
    generate_hashed_password,
    normalized_tls_subject,
    to_pkcs8,
)
from charms.opensearch.v0.opensearch_base_charm import PEER, OpenSearchBaseCharm
from charms.opensearch.v0.opensearch_distro import (
    OpenSearchHttpError,
    OpenSearchInstallError,
)
from charms.opensearch.v0.tls_constants import CertType
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
)
from ops.charm import (
    ActionEvent,
    InstallEvent,
    LeaderElectedEvent,
    RelationJoinedEvent,
    StartEvent,
    UpdateStatusEvent,
)
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

from opensearch import OpenSearchTarball

logger = logging.getLogger(__name__)


class OpenSearchOperatorCharm(OpenSearchBaseCharm):
    """This class represents the machine charm for OpenSearch."""

    def __init__(self, *args):
        super().__init__(*args, distro=OpenSearchTarball)  # OpenSearchSnap

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self.on.start, self._on_start)

        self.framework.observe(self.on[PEER].relation_joined, self._on_peer_relation_joined)

        self.framework.observe(self.on.update_status, self._on_update_status)

        # self.framework.observe(self.on.put_client_action, self._on_put_client)
        # self.framework.observe(self.on.delete_client_action, self._on_delete_client)

    def _on_install(self, event: InstallEvent) -> None:
        """Handle the install event."""
        self.unit.status = MaintenanceStatus("Installing OpenSearch...")
        try:
            self.opensearch.install()
        except OpenSearchInstallError:
            self.unit.status = BlockedStatus("Could not install OpenSearch.")
            event.defer()

    def _on_leader_elected(self, _: LeaderElectedEvent):
        """Handle the install event."""
        if self.app_peers_data.get("security_index_initialised", None) is not None:
            return

        self.unit.status = MaintenanceStatus("Configuring admin and clients security...")

        self._initialize_admin_user()
        self._configure_client_auth()

        self.unit.status = ActiveStatus()

    def _on_start(self, event: StartEvent):
        """Triggered when on start. Set the right node role."""
        try:
            nodes = self._get_nodes()
        except OpenSearchHttpError:
            event.defer()
            return

        self._initialize_node(nodes)

        is_cluster_bootstrapped = ClusterTopology.is_cluster_bootstrapped(nodes)
        cm_nodes_count = ClusterTopology.nodes_count_by_role(nodes).get("cluster_manager", 0)
        if not is_cluster_bootstrapped and cm_nodes_count == 2:
            # this condition means that we just added the last required CM node
            # cluster is bootstrapped now, we need to clean up the conf
            self.opensearch.config.delete(
                "opensearch.yml", "cluster.initial_cluster_manager_nodes"
            )

    def _on_peer_relation_joined(self, _: RelationJoinedEvent):
        """New node joining the cluster, we want to persist the admin certificate."""
        current_secrets = self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)

        # In the case of the first unit
        if current_secrets is None:
            return

        # Store the "Admin" certificate and key on disk
        path_prefix = f"{self.opensearch.paths.certs}/{CertType.APP_ADMIN.value}"
        self.opensearch.write_file(f"{path_prefix}.cert", current_secrets["cert"])
        self.opensearch.write_file(f"{path_prefix}.key", current_secrets["key"])

    def _on_update_status(self, event: UpdateStatusEvent):
        """On update status event.

        We want to periodically (every 6 hours) check if certs are expiring soon (in 24h),
        as a safeguard in case relation broken. As there will be data loss
        without the user noticing in case the cert of the unit transport layer expires.
        So we want to stop opensearch in that case, since it cannot be recovered from.
        """
        # if there are missing system requirements defer
        if self._deferred_because_missing_reqs(event):
            return

        # If relation broken - leave
        if self.model.get_relation("certificates") is not None:
            return

        # if node already shutdown - leave
        if not self.opensearch.is_node_up():
            return

        # See if the last check was made less than 6h ago, if yes - leave
        date_format = "%Y-%m-%d %H:%M:%S"
        last_cert_check = datetime.strptime(
            self.unit_peers_data.get("certs_exp_checked_at", "1970-01-01 00:00"), date_format
        )
        if (datetime.now() - last_cert_check).seconds < 6 * 3600:
            return

        certs = {
            CertType.UNIT_TRANSPORT: self.secrets.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT)[
                "cert"
            ],
            CertType.UNIT_HTTP: self.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP)["cert"],
        }
        if self.unit.is_leader():
            certs[CertType.APP_ADMIN] = self.secrets.get_object(Scope.APP, CertType.APP_ADMIN)[
                "cert"
            ]

        # keep certificates that are expiring in less than 24h
        for cert_type, cert in certs.items():
            hours = cert_expiration_remaining_hours(cert)
            if hours > 24:
                del certs[cert_type]

        if len(certs) > 0:
            missing = [cert.val for cert in certs.keys()]
            self.unit.status = BlockedStatus(
                f"The certificates: {', '.join(missing)} need to be refreshed."
            )

            # stop opensearch in case the Node-transport certificate expires.
            if certs.get(CertType.UNIT_TRANSPORT, None) is not None:
                self.opensearch.stop()

        self.unit_peers_data["certs_exp_checked_at"] = datetime.now().strftime(date_format)

    def on_tls_conf_set(
        self, event: CertificateAvailableEvent, scope: Scope, cert_type: CertType, renewal: bool
    ):
        """Called after certificate ready and stored on the corresponding scope databag.

        - Store the cert on the file system, on all nodes for APP certificates
        - Update the corresponding yaml conf files
        - Run the security admin script
        """
        # Get the list of stored secrets for this cert
        current_secrets = self.secrets.get_object(scope, cert_type.val)

        # In case of renewal of the unit transport layer cert - stop opensearch
        if renewal and cert_type == CertType.UNIT_TRANSPORT:
            self.opensearch.stop()

        # Store the cert and key on disk - must happen after opensearch stop for transport certs
        self._write_tls_resources(cert_type, current_secrets)

        if scope == Scope.UNIT:
            # node http or transport cert
            self._write_node_tls_conf(cert_type, current_secrets)
        else:
            # write the admin cert conf on all units, in case there is a leader loss + cert renewal
            self._write_admin_tls_conf(current_secrets)

        # start opensearch
        if not self.start_if_ready(event):
            return

        # initialize the security index if the admin certs are written on disk
        if (
            self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) is not None
            and self.app_peers_data.get("security_index_initialised", None) is None
        ):
            self._initialize_security_index(current_secrets)
            self.app_peers_data["security_index_initialised"] = "True"

    def start_if_ready(self, event: CertificateAvailableEvent) -> bool:
        """Start OpenSearch if TLS fully configured."""
        admin_secrets = self.secrets.get_object(Scope.APP, str(CertType.APP_ADMIN))
        if self.unit.is_leader() and (None in [admin_secrets, admin_secrets.get("cert", None)]):
            return False

        unit_transport_secrets = self.secrets.get_object(Scope.UNIT, str(CertType.UNIT_TRANSPORT))
        if None in [unit_transport_secrets, unit_transport_secrets.get("cert", None)]:
            return False

        unit_http_secrets = self.secrets.get_object(Scope.UNIT, str(CertType.UNIT_HTTP))
        if None in [unit_http_secrets, unit_http_secrets.get("cert", None)]:
            return False

        # if there are missing system requirements defer
        if self._deferred_because_missing_reqs(event):
            return False

        self.app.status = BlockedStatus("Waiting for OpenSearch to start...")
        self.opensearch.start()
        self.app.status = ActiveStatus()

        return True

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

    def _write_tls_resources(self, cert_type: CertType, secrets: Dict[str, any]):
        """Write certificates and keys on disk."""
        certs_dir = self.opensearch.paths.certs

        self.opensearch.write_file(
            f"{certs_dir}/{cert_type.val}.key",
            to_pkcs8(secrets["key"], secrets.get("key-password", None)),
        )
        self.opensearch.write_file(f"{certs_dir}/{cert_type.val}.cert", secrets["cert"])
        self.opensearch.write_file(f"{certs_dir}/root-ca.cert", secrets["ca"], override=False)

    def _initialize_node(self, nodes: List[Node]) -> None:
        """Set base config for each node in the cluster."""
        target_conf_file = "opensearch.yml"

        self.opensearch.config.put(
            target_conf_file, "cluster.name", f"{self.app.name}-{self.model.name}"
        )
        self.opensearch.config.put(target_conf_file, "node.name", self.unit_name)
        self.opensearch.config.put(
            target_conf_file, "network.host", ["_local_", self.opensearch.host]
        )

        roles = ClusterTopology.suggest_roles(nodes)
        self.opensearch.config.put(target_conf_file, "node.roles", roles)

        cm_ips = ClusterTopology.get_cluster_managers_ips(nodes)
        if len(cm_ips) > 0:
            self.opensearch.config.put(target_conf_file, "discovery.seed_hosts", cm_ips)

        if "cluster_manager" in roles and len(cm_ips) < 2:  # cluster NOT bootstrapped yet
            cm_names = ClusterTopology.get_cluster_managers_names(nodes)
            cm_names.append(self.unit_name)
            self.opensearch.config.put(
                target_conf_file, "cluster.initial_cluster_manager_nodes", cm_names
            )

        self.opensearch.config.put(target_conf_file, "path.data", self.opensearch.paths.data)
        self.opensearch.config.put(target_conf_file, "path.logs", self.opensearch.paths.logs)

        self.opensearch.config.replace("jvm.options", "=logs/", f"={self.opensearch.paths.logs}/")

        self.opensearch.config.put(target_conf_file, "plugins.security.disabled", False)
        self.opensearch.config.put(target_conf_file, "plugins.security.ssl.http.enabled", True)
        self.opensearch.config.put(
            target_conf_file, "plugins.security.ssl.transport.enforce_hostname_verification", True
        )

    def _initialize_admin_user(self):
        """Change default password of Admin user."""
        hashed_pwd, pwd = generate_hashed_password()
        self.secrets.put(Scope.APP, "admin_password", pwd)

        self.opensearch.config.put(
            "opensearch-security/internal_users.yml",
            "admin",
            {
                "hash": hashed_pwd,
                "reserved": True,  # this protects this resource from being updated on the dashboard or rest api
                "backend_roles": ["admin"],
                "description": "Admin user",
            },
        )

    def _configure_client_auth(self):
        """Configure TLS and basic http for clients."""
        # The security plugin will accept TLS client certs if certs but doesn't require them
        self.opensearch.config.put(
            "opensearch.yml", "plugins.security.ssl.http.clientauth_mode", "OPTIONAL"
        )

        security_config_file = "opensearch-security/config.yml"

        self.opensearch.config.put(
            security_config_file,
            "config/dynamic/authc/basic_internal_auth_domain/http_enabled",
            True,
        )

        self.opensearch.config.put(
            security_config_file,
            "config/dynamic/authc/clientcert_auth_domain/http_enabled",
            True,
        )

        self.opensearch.config.put(
            security_config_file,
            "config/dynamic/authc/clientcert_auth_domain/transport_enabled",
            True,
        )

    def _initialize_security_index(self, secrets: Dict[str, any]):
        """Run the security_admin script, it creates and initializes the opendistro_security index.

        IMPORTANT: must only run once per cluster, otherwise the index gets overrode
        """
        args = [
            f"-cd {self.opensearch.paths.conf}/opensearch-security/",
            f"-cn {self.app.name}-{self.model.name}",
            f"-h {self.unit_ip}",
            f"-cacert {self.opensearch.paths.certs}/root-ca.cert",
            f"-cert {self.opensearch.paths.certs}/{CertType.APP_ADMIN}.cert",
            f"-key {self.opensearch.paths.certs}/{CertType.APP_ADMIN}.key",
        ]

        admin_key_pwd = secrets.get("key-password", None)
        if admin_key_pwd is not None:
            args.append(f"-keypass {admin_key_pwd}")

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

    def _write_admin_tls_conf(self, secrets: Dict[str, any]):
        """Configures the admin certificate."""
        target_conf_file = "opensearch.yml"

        self.opensearch.config.put(
            target_conf_file,
            "plugins.security.authcz.admin_dn/{}",
            f"{normalized_tls_subject(secrets['subject'])}",
        )

    def _write_node_tls_conf(self, cert_type: CertType, secrets: Dict[str, any]):
        """Configures TLS for nodes."""
        logger.debug(f"_write_node_tls_conf: {cert_type}")
        target_conf_file = "opensearch.yml"
        target_conf_layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"

        self.opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemcert_filepath",
            f"{self.opensearch.paths.certs_relative}/{cert_type.val}.cert",
        )

        self.opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemkey_filepath",
            f"{self.opensearch.paths.certs_relative}/{cert_type.val}.key",
        )

        self.opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemtrustedcas_filepath",
            f"{self.opensearch.paths.certs_relative}/root-ca.cert",
        )

        key_pwd = secrets.get("key-password", None)
        if key_pwd is not None:
            self.opensearch.config.put(
                target_conf_file,
                f"plugins.security.ssl.{target_conf_layer}.pemkey_password",
                key_pwd,
            )

        self.opensearch.config.put(
            target_conf_file,
            "plugins.security.nodes_dn/{}",
            f"{normalized_tls_subject(secrets['subject'])}",
        )

    def _get_nodes(self) -> List[Node]:
        """Fetch the list of nodes of the cluster."""
        units_ips_map = units_ips(self, PEER)
        host: Optional[str] = None

        if len(units_ips_map) > 0:
            host = next(iter(units_ips_map.values()))  # get first value

        nodes: List[Node] = []
        if host is not None:
            response = self.opensearch.request("GET", "/_nodes", host=host)
            if "nodes" in response:
                for obj in response["nodes"].values():
                    nodes.append(Node(obj["name"], obj["roles"], obj["ip"]))

        return nodes


if __name__ == "__main__":
    main(OpenSearchOperatorCharm)
