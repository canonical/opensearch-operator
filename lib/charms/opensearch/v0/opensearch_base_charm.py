# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Operators."""
import logging
import math
import random
from abc import abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Type

from charms.opensearch.v0.constants_charm import (
    AdminUserInitProgress,
    CertsExpirationError,
    ClusterHealthRed,
    ClusterHealthYellow,
    NoNodeUpInCluster,
    RequestUnitServiceOps,
    SecurityIndexInitProgress,
    ServiceIsStopping,
    ServiceStartError,
    ServiceStopped,
    TLSNotFullyConfigured,
    TLSRelationBrokenError,
    TooManyNodesRemoved,
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
from charms.opensearch.v0.helper_networking import (
    get_host_ip,
    reachable_hosts,
    units_ips,
)
from charms.opensearch.v0.helper_security import (
    cert_expiration_remaining_hours,
    generate_hashed_password,
)
from charms.opensearch.v0.opensearch_config import OpenSearchConfig
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchHAError,
    OpenSearchHttpError,
    OpenSearchScaleDownError,
    OpenSearchStartError,
    OpenSearchStartTimeoutError,
    OpenSearchStopError,
)
from charms.opensearch.v0.opensearch_nodes_exclusions import (
    ALLOCS_TO_DELETE,
    VOTING_TO_DELETE,
    OpenSearchExclusions,
)
from charms.opensearch.v0.opensearch_tls import OpenSearchTLS
from charms.rolling_ops.v0.rollingops import RollingOpsManager
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
)
from ops.charm import (
    ActionEvent,
    CharmBase,
    LeaderElectedEvent,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationDepartedEvent,
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

        self.node_roles: List[str] = []
        self.opensearch_exclusions = OpenSearchExclusions(self)

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
        self.framework.observe(self.on[PEER].relation_departed, self._on_peer_relation_departed)
        self.framework.observe(
            self.on[STORAGE_NAME].storage_detaching, self._on_opensearch_data_storage_detaching
        )

        self.framework.observe(self.on.update_status, self._on_update_status)

        self.framework.observe(self.on.get_admin_secrets_action, self._on_get_admin_secrets_action)

    def _on_leader_elected(self, event: LeaderElectedEvent):
        """Handle leader election event."""
        if self.peers_data.get(Scope.APP, "security_index_initialised", False):
            # Leader election event happening after a previous leader got killed
            if not self.opensearch.is_node_up():
                event.defer()
            else:
                self._apply_cluster_health()
                self._compute_and_broadcast_updated_topology(self._get_nodes(True))
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

    def _on_peer_relation_changed(self, event: RelationChangedEvent):
        """Handle peer relation changes."""
        data = event.relation.data.get(event.unit if self.unit.is_leader() else event.app)
        if not data:
            return

        if self.unit.is_leader():
            cluster_health_color = data.get("health", "green")
            if cluster_health_color != "green":
                self.app.status = BlockedStatus(
                    ClusterHealthRed if cluster_health_color == "red" else ClusterHealthYellow
                )

            if data.get("bootstrap_contributor"):
                contributor_count = self.peers_data.get(
                    Scope.APP, "bootstrap_contributors_count", 0
                )
                self.peers_data.put(
                    Scope.APP, "bootstrap_contributors_count", contributor_count + 1
                )

            if data.get(VOTING_TO_DELETE) or data.get(ALLOCS_TO_DELETE):
                self.opensearch_exclusions.cleanup()

        # Run restart node on the concerned unit
        self._restart_unit_with_conf_if_needed()

    def _on_peer_relation_departed(self, event: RelationDepartedEvent):
        """Relation departed event."""
        if not (self.unit.is_leader() and self.opensearch.is_node_up()):
            return

        remaining_nodes = [
            node
            for node in self._get_nodes(True)
            if node.name != event.departing_unit.name.replace("/", "-")
        ]
        self._compute_and_broadcast_updated_topology(remaining_nodes)

    def _compute_and_broadcast_updated_topology(self, current_nodes: Optional[List[Node]]):
        """Compute cluster topology and broadcast role to change if any."""
        if not current_nodes:
            return

        node_to_update = ClusterTopology.node_with_new_roles(current_nodes)
        if node_to_update:
            self.peers_data.put_object(Scope.APP, "update-node-config", vars(node_to_update))

    def _on_opensearch_data_storage_detaching(self, _: StorageDetachingEvent):
        """Triggered when removing unit, Prior to the storage being detached."""
        # we currently block the scale down if majority removed
        if self.app.planned_units() < math.ceil(len(self.model.get_relation(PEER).units) / 2):
            self.unit.status = BlockedStatus(TooManyNodesRemoved)
            raise OpenSearchScaleDownError(TooManyNodesRemoved)

        # attempt lock acquisition through index creation, should crash if index already created
        # meaning another unit is holding the lock
        if self.opensearch.is_started() and self.alt_hosts:
            self.opensearch.request("PUT", "/.ops_stop", retries=3)

            # TODO query if current is CM + is_leader
            if self.unit.is_leader():
                remaining_nodes = [
                    node for node in self._get_nodes(True) if node.name != self.unit_name
                ]
                self._compute_and_broadcast_updated_topology(remaining_nodes)

        try:
            self._stop_opensearch()

            # check cluster status
            if not self.alt_hosts:
                self.app.status = BlockedStatus(ClusterHealthRed)
                raise OpenSearchHAError(NoNodeUpInCluster)

            health = self._apply_cluster_health(wait_for_green_first=True)
            if health == "red":
                raise OpenSearchHAError(ClusterHealthRed)
        finally:
            # release lock
            if self.alt_hosts:
                try:
                    self.opensearch.request("DELETE", "/.ops_stop", alt_hosts=self.alt_hosts)
                except OpenSearchHttpError:
                    # ignore, this just means the cleanup happened before but event got deferred
                    # because of another error
                    pass

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

        # if there are exclusions to be removed
        if self.unit.is_leader():
            self.opensearch_exclusions.cleanup()
            self._apply_cluster_health()

        # handle when/if certificates are expired
        self._check_certs_expiration(event)

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

    def on_tls_relation_broken(self, event: RelationBrokenEvent):
        """As long as all certificates are produced, we don't do anything."""
        if self._is_tls_fully_configured():
            return

        # Otherwise, we block.
        self.unit.status = BlockedStatus(TLSRelationBrokenError)

        try:
            self._stop_opensearch()
        except OpenSearchStopError:
            event.defer()

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

    def _start_opensearch(self, event: EventBase) -> None:  # noqa
        """Start OpenSearch if all resources configured."""
        if self.opensearch.is_started():
            self._post_start_init()
            self.status.clear(WaitingToStart)
            return

        if not self._can_service_start():
            self.peers_data.delete(Scope.UNIT, "starting")
            event.defer()
            return

        rel = self.model.get_relation(PEER)
        for unit in rel.units.union({self.unit}):
            if rel.data[unit].get("starting") == "True":
                event.defer()
                return

        self.peers_data.put(Scope.UNIT, "starting", True)

        updated_node_conf: Optional[Node] = None
        if self.peers_data.has(Scope.UNIT, "update-node-config"):
            updated_node_conf = Node.from_dict(
                self.peers_data.get_object(Scope.UNIT, "update-node-config")
            )

        try:
            # Retrieve the nodes of the cluster, needed to configure this node
            nodes = self._get_nodes(False)

            # Set the configuration of the node
            self._set_node_conf(nodes, updated_node_conf.roles if updated_node_conf else None)
        except OpenSearchHttpError:
            event.defer()
            self.peers_data.delete(Scope.UNIT, "starting")
            return

        try:
            self.unit.status = BlockedStatus(WaitingToStart)
            self.opensearch.start()
            self.status.clear(WaitingToStart)

            self._post_start_init()
        except OpenSearchStartTimeoutError:
            event.defer()
        except OpenSearchStartError:
            self.peers_data.delete(Scope.UNIT, "starting")
            self.unit.status = BlockedStatus(ServiceStartError)
            event.defer()

    def _post_start_init(self):
        """Initialization post OpenSearch start."""
        if self.unit.is_leader():
            # initialize the security index if needed and if the admin certs are written on disk
            if not self.peers_data.get(Scope.APP, "security_index_initialised"):
                admin_secrets = self.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
                self._initialize_security_index(admin_secrets)
                self.peers_data.put(Scope.APP, "security_index_initialised", True)

            self.peers_data.put(Scope.APP, "leader_ip", self.unit_ip)

        # cleanup bootstrap conf in the node
        if self.peers_data.get(Scope.UNIT, "bootstrap_contributor"):
            self._cleanup_bootstrap_conf_if_applies()

        # Remove the exclusions that could not be removed when no units were online
        self.opensearch_exclusions.delete_current()

        # Remove the 'starting' flag on the unit
        self.peers_data.delete(Scope.UNIT, "starting")

        # set "update complete flag" to true if it was an update
        current_update_node_conf = self.peers_data.get_object(Scope.UNIT, "update-node-config")
        if current_update_node_conf:
            self.peers_data.put_object(
                Scope.UNIT, "last-update-node-config", current_update_node_conf
            )

    def _stop_opensearch(self) -> None:
        """Stop OpenSearch if possible."""
        if not self.opensearch.is_started():
            return

        self.unit.status = WaitingStatus(ServiceIsStopping)

        # 1. Add current node to the voting + alloc exclusions
        self.opensearch_exclusions.add_current()

        # 2. stop the service
        self.opensearch.stop()
        self.unit.status = WaitingStatus(ServiceStopped)

        # 3. Remove the exclusions
        self.opensearch_exclusions.delete_current()

    def _restart_opensearch(self, event: EventBase) -> None:
        """Restart OpenSearch if possible."""
        if not self.peers_data.get(Scope.UNIT, "starting", False):
            try:
                self._stop_opensearch()
            except OpenSearchStopError as e:
                logger.error(e)
                event.defer()
                return

        self._start_opensearch(event)

    def _can_service_start(self) -> bool:
        """Return if the opensearch service can start."""
        # if there are any missing system requirements leave
        missing_sys_reqs = self.opensearch.missing_sys_requirements()
        if len(missing_sys_reqs) > 0:
            self.unit.status = BlockedStatus(" - ".join(missing_sys_reqs))
            return False

        # if self.peers_data.get(Scope.APP, "unit-busy-starting", False):
        #     return False

        # When a new unit joins, replica shards are automatically added to it. In order to prevent
        # overloading the cluster, units must be started one at a time. So we defer starting
        # opensearch until all shards in other units are in a "started" or "unassigned" state.
        if not self.unit.is_leader():
            if not self.peers_data.get(Scope.APP, "security_index_initialised", False):
                return False

            if self.peers_data.get(Scope.APP, "leader_ip"):
                try:
                    busy_shards = ClusterState.busy_shards_by_unit(
                        self.opensearch, self.peers_data.get(Scope.APP, "leader_ip")
                    )
                    if busy_shards:
                        message = WaitingForBusyShards.format(
                            " - ".join(
                                [f"{key}/{','.join(val)}" for key, val in busy_shards.items()]
                            )
                        )
                        self.unit.status = WaitingStatus(message)
                        return False

                    self.status.clear(
                        WaitingForBusyShards, pattern=Status.CheckPattern.Interpolated
                    )
                except OpenSearchHttpError:
                    # this means that the leader unit is not reachable (not started yet),
                    # meaning it's a new cluster, so we can safely start the OpenSearch service
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

    def _get_nodes(self, use_localhost: bool) -> List[Node]:
        """Fetch the list of nodes of the cluster, depending on the requester."""
        try:
            return ClusterTopology.nodes(self.opensearch, use_localhost, self.alt_hosts)
        except OpenSearchHttpError:
            if self.unit.is_leader() and not self.peers_data.get(
                Scope.APP, "security_index_initialised", False
            ):
                return []
            raise

    def _set_node_conf(self, nodes: List[Node], roles: Optional[List[str]] = None) -> None:
        """Set the configuration of the current node / unit."""
        computed_roles = roles or ClusterTopology.suggest_roles(nodes, self.app.planned_units())
        self.node_roles = computed_roles

        cm_names = ClusterTopology.get_cluster_managers_names(nodes)
        cm_ips = ClusterTopology.get_cluster_managers_ips(nodes)

        contribute_to_bootstrap = False
        if "cluster_manager" in computed_roles:
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
            computed_roles,
            cm_names,
            cm_ips,
            contribute_to_bootstrap,
        )

    def _cleanup_bootstrap_conf_if_applies(self) -> None:
        """Remove some conf props in the CM nodes that contributed to the cluster bootstrapping."""
        self.opensearch_config.cleanup_bootstrap_conf()

    def _restart_unit_with_conf_if_needed(self):
        """Trigger a restart event on the current unit if a recomputed conf was passed."""
        node_conf_update_app = self.peers_data.get_object(Scope.APP, "update-node-config")
        if not node_conf_update_app:
            return

        node = Node.from_dict(node_conf_update_app)
        if node.name != self.unit_name:
            return

        prev_update_node = self.peers_data.get_object(Scope.UNIT, "last-update-node-config")
        if prev_update_node:
            prev_update_node = Node.from_dict(prev_update_node)

        # already updated
        if node == prev_update_node:
            return

        node_conf_update_unit = self.peers_data.get_object(Scope.UNIT, "update-node-config")
        if not node_conf_update_unit:  # already emitted update / restart directive
            self.peers_data.put_object(Scope.UNIT, "update-node-config", node_conf_update_app)

        self.on[self.service_manager.name].acquire_lock.emit(
            callback_override="_restart_opensearch"
        )

    def _apply_cluster_health(self, wait_for_green_first: bool = False) -> str:
        """Fetch cluster health and set it on the app status."""
        response: Optional[Dict[str, any]] = None
        if wait_for_green_first:
            try:
                response = ClusterState.health(self.opensearch, True, alt_hosts=self.alt_hosts)
            except OpenSearchHttpError:
                # it timed out, settle with current status, fetched next without the 1min wait
                pass

        if not response:
            response = ClusterState.health(self.opensearch, False, alt_hosts=self.alt_hosts)

        status = response["status"].lower()
        status_messages_mapping = {
            "red": ClusterHealthRed,
            "yellow": ClusterHealthYellow,
        }
        if status in status_messages_mapping and self.unit.is_leader():
            self.app.status = BlockedStatus(status_messages_mapping[status])
        else:
            self.peers_data.put(Scope.UNIT, "health", status)
            if status == "green" and self.unit.is_leader():
                self.status.clear(ClusterHealthRed, app=True)
                self.status.clear(ClusterHealthYellow, app=True)

        return status

    def _check_certs_expiration(self, event: UpdateStatusEvent) -> None:
        """Checks the certificates' expiration."""
        date_format = "%Y-%m-%d %H:%M:%S"
        last_cert_check = datetime.strptime(
            self.peers_data.get(Scope.UNIT, "certs_exp_checked_at", "1970-01-01 00:00:00"),
            date_format,
        )

        # See if the last check was made less than 6h ago, if yes - leave
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
                try:
                    self._stop_opensearch()
                except OpenSearchStopError:
                    event.defer()
                    return

        self.peers_data.put(
            Scope.UNIT, "certs_exp_checked_at", datetime.now().strftime(date_format)
        )

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
    def alt_hosts(self) -> Optional[List[str]]:
        """Return an alternative host (of another node) in case the current is offline."""
        all_units_ips = units_ips(self, PEER)
        all_hosts = list(all_units_ips.values())
        random.shuffle(all_hosts)

        if not all_hosts:
            return None

        return reachable_hosts([host for host in all_hosts if host != self.unit_ip])
