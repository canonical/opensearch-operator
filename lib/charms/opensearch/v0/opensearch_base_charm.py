# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Operators."""
import json
import logging
import random
from abc import abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Type

from charms.opensearch.v0.constants_charm import (
    AdminUserInitProgress,
    CertsExpirationError,
    ClusterHealthRed,
    ClusterHealthYellow,
    RequestUnitServiceOps,
    SecurityIndexInitProgress,
    ServiceIsStopping,
    ServiceStartError,
    ServiceStopFailed,
    ServiceStopped,
    TLSNotFullyConfigured,
    TLSRelationBrokenError,
    WaitingForBusyShards,
    WaitingToStart,
)
from charms.opensearch.v0.constants_tls import TLS_RELATION, CertType
from charms.opensearch.v0.helper_charm import Status
from charms.opensearch.v0.helper_cluster import ClusterState, ClusterTopology, Node
from charms.opensearch.v0.helper_databag import (
    RelationDataStore,
    Scope,
    SecretsDataStore,
)
from charms.opensearch.v0.helper_networking import get_host_ip, units_ips
from charms.opensearch.v0.helper_security import (
    cert_expiration_remaining_hours,
    generate_hashed_password,
)
from charms.opensearch.v0.opensearch_config import OpenSearchConfig
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchHAError,
    OpenSearchHttpError,
    OpenSearchStartError,
    OpenSearchStopError,
)
from charms.opensearch.v0.opensearch_nodes_exclusions import NodeExclusionInCharmOps
from charms.opensearch.v0.opensearch_tls import OpenSearchTLS
from charms.rolling_ops.v0.rollingops import RollingOpsManager
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
)
from ops.charm import (
    ActionEvent,
    CharmBase,
    LeaderElectedEvent,
    RelationChangedEvent,
    RelationJoinedEvent,
    StartEvent,
    StorageDetachingEvent,
    UpdateStatusEvent,
)
from ops.framework import EventBase
from ops.model import BlockedStatus, MaintenanceStatus, WaitingStatus

# The unique Charmhub library identifier, never change it
LIBID = "cba015bae34642baa1b6bb27bb35a2f7"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


PEER = "opensearch-peers"
SERVICE_MANAGER = "service"
STORAGE_NAME = "opensearch-data"


logger = logging.getLogger(__name__)


class OpenSearchBaseCharm(CharmBase):
    """Base class for OpenSearch charms."""

    def __init__(self, *args, distro: Type[OpenSearchDistribution] = None):
        super().__init__(*args)

        if distro is None:
            raise ValueError("The type of the opensearch distro must be specified.")

        self.opensearch = distro(self, PEER)
        self.opensearch_config = OpenSearchConfig(self.opensearch)
        self.peers_data = RelationDataStore(self, PEER)
        self.secrets = SecretsDataStore(self, PEER)
        self.tls = OpenSearchTLS(self, TLS_RELATION)
        self.status = Status(self)
        self.service_manager = RollingOpsManager(
            self, relation=SERVICE_MANAGER, callback=self._start_opensearch
        )

        self.framework.observe(self.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self.on.start, self._on_start)

        self.framework.observe(self.on[PEER].relation_joined, self._on_peer_relation_joined)
        self.framework.observe(self.on[PEER].relation_changed, self._on_peer_relation_changed)
        self.framework.observe(
            self.on[STORAGE_NAME].storage_detaching, self._on_opensearch_data_storage_detaching
        )

        self.framework.observe(self.on.update_status, self._on_update_status)

        self.framework.observe(self.on.get_admin_secrets_action, self._on_get_admin_secrets_action)

    def _on_leader_elected(self, _: LeaderElectedEvent):
        """Handle leader election event."""
        if self.peers_data.get(Scope.APP, "security_index_initialised"):
            return

        if not self.peers_data.get(Scope.APP, "admin_user_initialized"):
            self.unit.status = MaintenanceStatus(AdminUserInitProgress)
            self._initialize_admin_user()
            self.peers_data.put(Scope.APP, "admin_user_initialized", True)
            self.status.clear(AdminUserInitProgress)

    def _on_start(self, event: StartEvent):
        """Triggered when on start. Set the right node role."""
        if self.opensearch.is_started():
            if self.peers_data.get(Scope.APP, "security_index_initialised"):
                # in the case where it was on WaitingToStart status, event got deferred
                # and the service started in between, put status back to active
                self.status.clear(WaitingToStart)

            # cleanup bootstrap conf in the node if existing
            if self.peers_data.get(Scope.UNIT, "bootstrap_contributor"):
                self._cleanup_bootstrap_conf_if_applies()

            return

        if not self._is_tls_fully_configured():
            self.unit.status = BlockedStatus(TLSNotFullyConfigured)
            event.defer()
            return

        # configure clients auth
        self.opensearch_config.set_client_auth()

        # request the start of OpenSearch
        self.unit.status = WaitingStatus(RequestUnitServiceOps.format("start"))
        self.on[self.service_manager.name].acquire_lock.emit(callback_override="_start_opensearch")

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

    def _on_opensearch_data_storage_detaching(self, event: StorageDetachingEvent):
        """Triggered when removing unit, Prior to the storage being detached."""
        remaining_nodes = [node for node in self._get_nodes() if node.name != self.unit_name]

        node_to_update = ClusterTopology.node_with_new_roles(remaining_nodes)
        if node_to_update:
            self.peers_data.put_object(Scope.UNIT, "updated-node-config", vars(node_to_update))

        self._stop_opensearch(event)

        # check cluster status
        host, alt_hosts = self._hosts()
        if not host and not alt_hosts:
            raise OpenSearchHAError("No host is up in this cluster.")

        response = self.opensearch.request(
            "GET",
            "/_cluster/health?wait_for_status=green&timeout=1m",
            host=host,
            alt_hosts=alt_hosts,
        )
        status = response["status"].lower()

        if status == "green":
            return

        if status == "yellow":
            self.app.status = BlockedStatus(ClusterHealthYellow)
            return

        raise OpenSearchHAError(ClusterHealthRed)

    def _on_peer_relation_changed(self, event: RelationChangedEvent):
        """Handle peer relation changes."""
        data = event.relation.data.get(event.unit)

        if self.unit.is_leader():
            if data:
                if data.get("bootstrap_contributor"):
                    contributor_count = self.peers_data.get(
                        Scope.APP, "bootstrap_contributors_count", 0
                    )
                    self.peers_data.put(
                        Scope.APP, "bootstrap_contributors_count", contributor_count + 1
                    )

                in_charm_exclusions = self.opensearch.exclusions.in_charm

                voting_exclusions = data.get(NodeExclusionInCharmOps.RemoveFromAllocExclusion)
                if voting_exclusions:
                    in_charm_exclusions.set_voting_exclusions_for_removal()
                else:
                    in_charm_exclusions.clear_voting_exclusions()

                if data.get(NodeExclusionInCharmOps.RemoveFromAllocExclusion):
                    in_charm_exclusions.set_allocation_exclusions_for_removal(self.unit_name)

        updated_node_conf = data.get("updated-node-config")
        if updated_node_conf:
            node = json.loads(updated_node_conf)
            if node.name == self.unit_name:
                self._set_node_conf(self._get_nodes(), node.roles)
                self.on[self.service_manager.name].acquire_lock.emit(
                    callback_override="_restart_opensearch"
                )

    def _on_update_status(self, event: UpdateStatusEvent):
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
            self.peers_data.get(Scope.UNIT, "certs_exp_checked_at", "1970-01-01 00:00:00"),
            date_format,
        )
        if (datetime.now() - last_cert_check).seconds < 6 * 3600:
            return

        certs = self.secrets.get_unit_certificates()

        # keep certificates that are expiring in less than 24h
        for cert_type, cert in certs.items():
            hours = cert_expiration_remaining_hours(cert)
            if hours > 24 * 7:
                del certs[cert_type]

        if certs:
            missing = [cert.val for cert in certs.keys()]
            self.unit.status = BlockedStatus(CertsExpirationError.format(", ".join(missing)))

            # stop opensearch in case the Node-transport certificate expires.
            if certs.get(CertType.UNIT_TRANSPORT) is not None:
                self._stop_opensearch(event)

        self.peers_data.put(
            Scope.UNIT, "certs_exp_checked_at", datetime.now().strftime(date_format)
        )

    def _on_get_admin_secrets_action(self, event: ActionEvent):
        """Return the password and cert chain for the admin user of the cluster."""
        password = self.secrets.get(Scope.APP, "admin_password")

        chain = ""
        admin_secrets = self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        if admin_secrets and admin_secrets.get("chain"):
            chain = "\n".join(admin_secrets["chain"][::-1])

        event.set_results({"password": password if password else "", "chain": chain})

    def on_tls_conf_set(
        self, _: CertificateAvailableEvent, scope: Scope, cert_type: CertType, renewal: bool
    ):
        """Called after certificate ready and stored on the corresponding scope databag.

        - Store the cert on the file system, on all nodes for APP certificates
        - Update the corresponding yaml conf files
        - Run the security admin script
        """
        # Get the list of stored secrets for this cert
        current_secrets = self.secrets.get_object(scope, cert_type.val)

        # Store cert/key on disk - must happen after opensearch stop for transport certs renewal
        self._store_tls_resources(cert_type, current_secrets)

        if scope == Scope.UNIT:
            # node http or transport cert
            self.opensearch_config.set_node_tls_conf(cert_type, current_secrets)
        else:
            # write the admin cert conf on all units, in case there is a leader loss + cert renewal
            self.opensearch_config.set_admin_tls_conf(current_secrets)

        # In case of renewal of the unit transport layer cert - restart opensearch
        if renewal and cert_type == CertType.UNIT_TRANSPORT:
            self.on[self.service_manager.name].acquire_lock.emit(
                callback_override="_restart_opensearch"
            )

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
        if not self.peers_data.get(Scope.APP, "admin_user_initialized"):
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

    def _start_opensearch(self, event: EventBase) -> None:
        """Start OpenSearch if all resources configured."""
        if not self._can_service_start():
            event.defer()
            return

        try:
            # Retrieve the nodes of the cluster, needed to configure this node
            nodes = self._get_nodes()
        except OpenSearchHttpError:
            event.defer()
            return

        # Set the configuration of the node
        self._set_node_conf(nodes)

        try:
            self.unit.status = BlockedStatus(WaitingToStart)
            self.opensearch.start()
            self.status.clear(WaitingToStart)
        except OpenSearchStartError as e:
            logger.debug(e)
            self.unit.status = BlockedStatus(ServiceStartError)
            event.defer()
            return

        if self.unit.is_leader():
            # initialize the security index if needed and if the admin certs are written on disk
            if not self.peers_data.get(Scope.APP, "security_index_initialised"):
                admin_secrets = self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
                self._initialize_security_index(admin_secrets)
                self.peers_data.put(Scope.APP, "security_index_initialised", True)

            self.peers_data.put(Scope.APP, "leader_ip", self.unit_ip)

        # Remove the exclusions that could not be removed when no units were online
        self._remove_previously_failed_exclusions()

        # cleanup bootstrap conf in the node
        if self.peers_data.get(Scope.UNIT, "bootstrap_contributor"):
            self._cleanup_bootstrap_conf_if_applies()

    def _stop_opensearch(self, event: EventBase) -> None:
        """Stop OpenSearch if possible."""
        try:
            self.unit.status = WaitingStatus(ServiceIsStopping)
            self.opensearch.stop()
            self.unit.status = WaitingStatus(ServiceStopped)
        except OpenSearchStopError as e:
            logger.debug(e)
            self.unit.status = BlockedStatus(ServiceStopFailed)
            event.defer()

    def _restart_opensearch(self, event: EventBase) -> None:
        """Restart OpenSearch if possible."""
        self._stop_opensearch(event)
        self._start_opensearch(event)

    def _can_service_start(self):
        """Return if the opensearch service can start."""
        # if there are any missing system requirements leave
        missing_sys_reqs = self.opensearch.missing_sys_requirements()
        if len(missing_sys_reqs) > 0:
            self.unit.status = BlockedStatus(" - ".join(missing_sys_reqs))
            return False

        # When a new unit joins, replica shards are automatically added to it. In order to prevent
        # overloading the cluster, units must be started one at a time. So we defer starting
        # opensearch until all shards in other units are in a "started" or "unassigned" state.
        if not self.unit.is_leader() and self.peers_data.get(Scope.APP, "leader_ip"):
            try:
                busy_shards = ClusterState.busy_shards_by_unit(
                    self.opensearch, self.peers_data.get(Scope.APP, "leader_ip")
                )
                if busy_shards:
                    message = WaitingForBusyShards.format(
                        " - ".join([f"{key}/{','.join(val)}" for key, val in busy_shards.items()])
                    )
                    self.unit.status = WaitingStatus(message)
                    return False

                self.status.clear(WaitingForBusyShards, pattern=Status.CheckPattern.Interpolated)
            except OpenSearchHttpError:
                # this means that the leader unit is not reachable (not started yet),
                # meaning that it's a new cluster, so we can safely start the OpenSearch service
                pass

        return True

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

    def _initialize_security_index(self, admin_secrets: Dict[str, any]) -> None:
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
        self.status.clear(SecurityIndexInitProgress)

    def _remove_previously_failed_exclusions(self) -> None:
        """Remove the exclusions that failed to be cleared when no units where online."""
        # Remove the voting exclusions for cluster_manager nodes
        if self.peers_data.get(Scope.APP, NodeExclusionInCharmOps.RemoveVotingExclusions):
            self.opensearch.exclusions.remove_voting_exclusions()

        # Remove the nodes allocations exclusions for data
        if self.peers_data.get(Scope.APP, NodeExclusionInCharmOps.RemoveFromAllocExclusion):
            self.opensearch.exclusions.remove_allocation_exclusions(
                self.peers_data.get(Scope.APP, NodeExclusionInCharmOps.RemoveFromAllocExclusion)
            )

    def _get_nodes(self) -> List[Node]:
        """Fetch the list of nodes of the cluster, depending on the requester."""

        def fetch() -> List[Node]:
            """Fetches the list of nodes through HTTP."""
            host, alt_hosts = self._hosts()

            nodes: List[Node] = []
            if host is not None:
                response = self.opensearch.request(
                    "GET", "/_nodes", host=host, alt_hosts=alt_hosts
                )
                if "nodes" in response:
                    for obj in response["nodes"].values():
                        nodes.append(Node(obj["name"], obj["roles"], obj["ip"]))

            return nodes

        try:
            return fetch()
        except OpenSearchHttpError:
            if self.unit.is_leader() and not self.peers_data.get(
                Scope.APP, "security_index_initialised"
            ):
                return []
            raise

    def _hosts(self) -> Tuple[Optional[str], List[str]]:
        """Fetch the hosts of this cluster, besides the current unit host."""
        host: Optional[str] = None
        alt_hosts: Optional[List[str]] = None

        all_hosts = list(units_ips(self, PEER).values())
        try:
            all_hosts = all_hosts.remove(self.unit_ip)
        except ValueError:
            pass

        if all_hosts:
            host = all_hosts.pop(0)  # get first value
            alt_hosts = all_hosts

        return host, alt_hosts

    def _set_node_conf(self, nodes: List[Node], roles: Optional[str] = None) -> None:
        """Set the configuration of the current node / unit."""
        roles = roles or ClusterTopology.suggest_roles(nodes, self.app.planned_units())

        cm_names = ClusterTopology.get_cluster_managers_names(nodes)
        cm_ips = ClusterTopology.get_cluster_managers_ips(nodes)

        contribute_to_bootstrap = False
        if "cluster_manager" in roles:
            cm_names.append(self.unit_name)
            cm_ips.append(self.unit_ip)

            cms_in_bootstrap = self.peers_data.get(Scope.APP, "bootstrap_contributors_count", 0)
            if cms_in_bootstrap < self.app.planned_units():
                contribute_to_bootstrap = True

                if self.unit.is_leader():
                    self.peers_data.put(
                        Scope.APP, "bootstrap_contributors_count", cms_in_bootstrap + 1
                    )

                # indicates that this unit is part of the "initial cm nodes"
                self.peers_data.put(Scope.UNIT, "bootstrap_contributor", True)

        self.opensearch_config.set_node(
            self.app.name,
            self.model.name,
            self.unit_name,
            roles,
            cm_names,
            cm_ips,
            contribute_to_bootstrap,
        )

    def _cleanup_bootstrap_conf_if_applies(self) -> None:
        """Remove some conf props in the CM nodes that contributed to the cluster bootstrapping."""
        self.opensearch_config.cleanup_bootstrap_conf()

    @abstractmethod
    def _store_tls_resources(
        self, cert_type: CertType, secrets: Dict[str, any], override_admin: bool = True
    ):
        """Write certificates and keys on disk."""
        pass

    @abstractmethod
    def _are_all_tls_resources_stored(self):
        """Check if all TLS resources are stored on disk."""
        pass

    @property
    def unit_ip(self) -> str:
        """IP address of the current unit."""
        return get_host_ip(self, PEER)

    @property
    def unit_name(self) -> str:
        """Name of the current unit."""
        return self.unit.name.replace("/", "-")

    @property
    def unit_id(self) -> int:
        """ID of the current unit."""
        return int(self.unit.name.split("/")[1])

    @property
    def alternative_host(self) -> str:
        """Return an alternative host (of another node) in case the current is offline."""
        all_units_ips = units_ips(self, PEER)
        return random.choice(list(all_units_ips.values()))
