#!/usr/bin/env python3

# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""
import logging
from datetime import datetime
from os.path import exists
from typing import Dict, List, Optional

from charms.opensearch.v0.constants_charm import (
    AdminUserInitProgress,
    CertsExpirationError,
    InstallError,
    InstallProgress,
    SecurityIndexInitProgress,
    TLSNotFullyConfigured,
    TLSRelationBrokenError,
    WaitingForBusyShards,
    WaitingToStart,
)
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_cluster import ClusterState, ClusterTopology, Node
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.helper_networking import units_ips
from charms.opensearch.v0.helper_security import (
    cert_expiration_remaining_hours,
    generate_hashed_password,
    to_pkcs8,
)
from charms.opensearch.v0.opensearch_base_charm import (
    PEER,
    OpenSearchBaseCharm,
    StatusCheckPattern,
)
from charms.opensearch.v0.opensearch_distro import (
    OpenSearchHttpError,
    OpenSearchInstallError,
    OpenSearchStartError,
)
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
)
from ops.charm import (
    ActionEvent,
    InstallEvent,
    LeaderElectedEvent,
    RelationChangedEvent,
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
        self.framework.observe(self.on[PEER].relation_changed, self._on_peer_relation_changed)

        self.framework.observe(self.on.update_status, self._on_update_status)

        self.framework.observe(self.on.get_admin_secrets_action, self._on_get_admin_secrets_action)

    def _on_install(self, _: InstallEvent) -> None:
        """Handle the install event."""
        self.unit.status = MaintenanceStatus(InstallProgress)
        try:
            self.opensearch.install()
            self.unit.status = ActiveStatus()
        except OpenSearchInstallError:
            self.unit.status = BlockedStatus(InstallError)

    def _on_leader_elected(self, _: LeaderElectedEvent):
        """Handle leader election event."""
        self.app_peers_data["leader_ip"] = self.unit_ip

        if self.app_peers_data.get("security_index_initialised"):
            return

        if not self.app_peers_data.get("admin_user_initialized"):
            self.unit.status = MaintenanceStatus(AdminUserInitProgress)
            self._initialize_admin_user()
            self.app_peers_data["admin_user_initialized"] = "True"
            self.unit.status = ActiveStatus()

    def _on_start(self, event: StartEvent):
        """Triggered when on start. Set the right node role."""
        if self.opensearch.is_started() and self.app_peers_data.get("security_index_initialised"):
            # in the case where it was on WaitingToStart status, event got deferred
            # and the service started in between, put status back to active
            self.clear_status(WaitingToStart)
            return

        if not self._is_tls_fully_configured():
            self.unit.status = BlockedStatus(TLSNotFullyConfigured)
            event.defer()
            return

        # reset status to active if it was TLSNotFullyConfigured
        self.clear_status(TLSNotFullyConfigured)

        # configure clients auth
        self.opensearch_config.set_client_auth()

        try:
            # Retrieve the nodes of the cluster, needed to configure this node
            nodes = self._get_nodes()
        except OpenSearchHttpError:
            event.defer()
            return

        # Set the configuration of the node
        self._set_node_conf(nodes)

        # Remove some config entries when cluster bootstrapped
        self._cleanup_conf_if_bootstrapped(nodes)

        # start opensearch
        if not self._start_opensearch():
            event.defer()
            return

        # initialize the security index if the admin certs are written on disk
        if self.unit.is_leader() and self.app_peers_data.get("security_index_initialised") is None:
            admin_secrets = self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
            self._initialize_security_index(admin_secrets)
            self.app_peers_data["security_index_initialised"] = "True"

    def _on_peer_relation_joined(self, event: RelationJoinedEvent):
        """New node joining the cluster."""
        current_secrets = self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)

        # In the case of the first units before TLS is initialized
        if not current_secrets:
            if not self.unit.is_leader():
                event.defer()
            return

        # in the case the cluster was bootstrapped with multiple units at the same time
        # and the certificates have not been generated yet
        if not current_secrets.get("cert") or not current_secrets.get("chain"):
            event.defer()
            return

        # Store the "Admin" certificate, key and CA on the disk of the new unit
        self._store_tls_resources(CertType.APP_ADMIN, current_secrets, override_admin=False)

    def _on_peer_relation_changed(self, event: RelationChangedEvent):
        """Restart node when cert renewal for the transport layer."""
        if self.unit_peers_data.get("must_reboot_node") == "True":
            try:
                self.opensearch.restart()
                del self.unit_peers_data["must_reboot_node"]
            except OpenSearchStartError:
                event.defer()

    def _on_update_status(self, _: UpdateStatusEvent):
        """On update status event.

        We want to periodically check for 2 things:
        1- The system requirements are still met
        2- every 6 hours check if certs are expiring soon (in 7 days),
            as a safeguard in case relation broken. As there will be data loss
            without the user noticing in case the cert of the unit transport layer expires.
            So we want to stop opensearch in that case, since it cannot be recovered from.
        """
        # if there are missing system requirements defer
        missing_sys_reqs = self.opensearch.missing_sys_requirements()
        if len(missing_sys_reqs) > 0:
            self.unit.status = BlockedStatus(" - ".join(missing_sys_reqs))
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
            if hours > 24 * 7:
                del certs[cert_type]

        if len(certs) > 0:
            missing = [cert.val for cert in certs.keys()]
            self.unit.status = BlockedStatus(CertsExpirationError.format(", ".join(missing)))

            # stop opensearch in case the Node-transport certificate expires.
            if certs.get(CertType.UNIT_TRANSPORT) is not None:
                self.opensearch.stop()

        self.unit_peers_data["certs_exp_checked_at"] = datetime.now().strftime(date_format)

    def _on_get_admin_secrets_action(self, event: ActionEvent):
        """Return the password and cert chain for the admin user of the cluster."""
        password = self.secrets.get(Scope.APP, "admin_password")

        chain = ""
        admin_secrets = self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        if admin_secrets and admin_secrets.get("chain"):
            chain = "\n".join(admin_secrets["chain"][::-1])

        event.set_results({"password": password if password else "", "chain": chain})

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
        should_restart = False
        if renewal and cert_type == CertType.UNIT_TRANSPORT:
            self.opensearch.stop()
            should_restart = True

        # Store cert/key on disk - must happen after opensearch stop for transport certs renewal
        self._store_tls_resources(cert_type, current_secrets)

        if scope == Scope.UNIT:
            # node http or transport cert
            self.opensearch_config.set_node_tls_conf(cert_type, current_secrets)
        else:
            # write the admin cert conf on all units, in case there is a leader loss + cert renewal
            self.opensearch_config.set_admin_tls_conf(current_secrets)

        if should_restart:
            self.unit_peers_data["must_reboot_node"] = "True"

    def on_tls_relation_broken(self):
        """As long as all certificates are produced, we don't do anything."""
        if self._is_tls_fully_configured():
            return

        # Otherwise, we block.
        self.unit.status = BlockedStatus(TLSRelationBrokenError)
        self.opensearch.stop()

    def _is_tls_fully_configured(self) -> bool:
        """Check if TLS fully configured meaning the admin user configured & 3 certs present."""
        # In case the initialisation of the admin user is not finished yet
        if not self.app_peers_data.get("admin_user_initialized"):
            return False

        admin_secrets = self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        if not admin_secrets or not admin_secrets.get("cert") or not admin_secrets.get("chain"):
            return False

        unit_transport_secrets = self.secrets.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val)
        if not unit_transport_secrets or not unit_transport_secrets.get("cert"):
            return False

        unit_http_secrets = self.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP.val)
        if not unit_http_secrets or not unit_http_secrets.get("cert"):
            return False

        return self._are_all_tls_resources_stored()

    def _start_opensearch(self) -> bool:
        """Start OpenSearch if all resources configured."""
        # if there are any missing system requirements leave
        missing_sys_reqs = self.opensearch.missing_sys_requirements()
        if len(missing_sys_reqs) > 0:
            self.unit.status = BlockedStatus(" - ".join(missing_sys_reqs))
            return False

        # check if there are shards that are "busy" or "relocating"
        # defer the start until all the shards are "started"
        if self.app_peers_data.get("leader_ip"):
            try:
                busy_shards = ClusterState.busy_shards_by_unit(
                    self.opensearch, self.app_peers_data.get("leader_ip")
                )
                if busy_shards:
                    message = WaitingForBusyShards.format(
                        " - ".join([f"{key}/{','.join(val)}" for key, val in busy_shards.items()])
                    )
                    self.unit.status = BlockedStatus(message)
                    return False

                self.clear_status(WaitingForBusyShards, pattern=StatusCheckPattern.Interpolated)
            except OpenSearchHttpError:
                # this means that the leader unit is not reachable (not started yet),
                # meaning that it's a new cluster, so we can safely start the OpenSearch service
                pass

        try:
            self.unit.status = BlockedStatus(WaitingToStart)
            self.opensearch.start()
            self.unit.status = ActiveStatus()

            return True
        except OpenSearchStartError:
            return False

    def _store_tls_resources(
        self, cert_type: CertType, secrets: Dict[str, any], override_admin: bool = True
    ):
        """Write certificates and keys on disk."""
        certs_dir = self.opensearch.paths.certs

        self.opensearch.write_file(
            f"{certs_dir}/{cert_type.val}.key",
            to_pkcs8(secrets["key"], secrets.get("key-password")),
        )
        self.opensearch.write_file(f"{certs_dir}/{cert_type.val}.cert", secrets["cert"])
        self.opensearch.write_file(f"{certs_dir}/root-ca.cert", secrets["ca"], override=False)

        if cert_type == CertType.APP_ADMIN:
            self.opensearch.write_file(
                f"{certs_dir}/chain.pem",
                "\n".join(secrets["chain"][::-1]),
                override=override_admin,
            )

    def _are_all_tls_resources_stored(self):
        """Check if all TLS resources are stored on disk."""
        certs_dir = self.opensearch.paths.certs
        for cert_type in [CertType.APP_ADMIN, CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            for extension in ["key", "cert"]:
                if not exists(f"{certs_dir}/{cert_type.val}.{extension}"):
                    return False

        return exists(f"{certs_dir}/chain.pem") and exists(f"{certs_dir}/root-ca.cert")

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

    def _initialize_security_index(self, admin_secrets: Dict[str, any]):
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

        admin_key_pwd = admin_secrets.get("key-password", None)
        if admin_key_pwd is not None:
            args.append(f"-keypass {admin_key_pwd}")

        self.unit.status = MaintenanceStatus(SecurityIndexInitProgress)
        self.opensearch.run_script(
            "plugins/opensearch-security/tools/securityadmin.sh", " ".join(args)
        )
        self.unit.status = ActiveStatus()

    def _get_nodes(self) -> List[Node]:
        """Fetch the list of nodes of the cluster, depending on the requester."""

        def fetch() -> List[Node]:
            """Fetches the list of nodes through HTTP."""
            host: Optional[str] = None

            all_units_ips = units_ips(self, PEER).values()
            if all_units_ips:
                host = next(iter(all_units_ips))  # get first value

            nodes: List[Node] = []
            if host is not None:
                response = self.opensearch.request("GET", "/_nodes", host=host)
                if "nodes" in response:
                    for obj in response["nodes"].values():
                        nodes.append(Node(obj["name"], obj["roles"], obj["ip"]))

            return nodes

        try:
            return fetch()
        except OpenSearchHttpError:
            if self.unit.is_leader() and not self.app_peers_data.get("security_index_initialised"):
                return []
            raise

    def _set_node_conf(self, nodes: List[Node]) -> None:
        """Set the configuration of the current node / unit."""
        roles = ClusterTopology.suggest_roles(nodes)

        cm_names = ClusterTopology.get_cluster_managers_names(nodes)
        cm_ips = ClusterTopology.get_cluster_managers_ips(nodes)
        if "cluster_manager" in roles:
            cm_names.append(self.unit_name)
            cm_ips.append(self.unit_ip)

        self.opensearch_config.set_node(
            self.app.name,
            self.model.name,
            self.unit_name,
            roles,
            cm_names,
            cm_ips,
        )

    def _cleanup_conf_if_bootstrapped(self, nodes: List[Node]) -> None:
        """Remove some conf props when cluster is bootstrapped."""
        remaining_nodes_for_bootstrap = ClusterTopology.remaining_nodes_for_bootstrap(nodes)
        if remaining_nodes_for_bootstrap == 0:
            # this condition means that we just added the last required CM node
            # the cluster is bootstrapped now, we need to clean up the conf on the CM nodes
            self.opensearch_config.cleanup_conf_if_bootstrapped()


if __name__ == "__main__":
    main(OpenSearchOperatorCharm)
