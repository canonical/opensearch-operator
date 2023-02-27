# Copyright 2023 Canonical Ltd.
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
    ClientRelationName,
    ClusterHealthRed,
    ClusterHealthYellow,
    NoNodeUpInCluster,
    PeerRelationName,
    RequestUnitServiceOps,
    SecurityIndexInitProgress,
    ServiceIsStopping,
    ServiceStartError,
    ServiceStopped,
    TLSNotFullyConfigured,
    TLSRelationBrokenError,
    TooManyNodesRemoved,
    WaitingForBusyShards,
    WaitingForSpecificBusyShards,
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
    generate_password,
)
from charms.opensearch.v0.opensearch_config import OpenSearchConfig
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchError,
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
from charms.opensearch.v0.opensearch_relation_provider import OpenSearchProvider
from charms.opensearch.v0.opensearch_tls import OpenSearchTLS
from charms.opensearch.v0.opensearch_users import OpenSearchUserManager
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


SERVICE_MANAGER = "service"
STORAGE_NAME = "opensearch-data"


logger = logging.getLogger(__name__)


class OpenSearchBaseCharm(CharmBase):
    """Base class for OpenSearch charms."""

    def __init__(self, *args, distro: Type[OpenSearchDistribution] = None):
        super().__init__(*args)

        if distro is None:
            raise ValueError("The type of the opensearch distro must be specified.")

        self.opensearch = distro(self, PeerRelationName)
        self.opensearch_config = OpenSearchConfig(self.opensearch)
        self.opensearch_exclusions = OpenSearchExclusions(self)
        self.peers_data = RelationDataStore(self, PeerRelationName)
        self.secrets = SecretsDataStore(self, PeerRelationName)
        self.tls = OpenSearchTLS(self, TLS_RELATION)
        self.status = Status(self)

        self.service_manager = RollingOpsManager(
            self, relation=SERVICE_MANAGER, callback=self._start_opensearch
        )
        self.user_manager = OpenSearchUserManager(self)
        self.opensearch_provider = OpenSearchProvider(self)

        self.framework.observe(self.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.update_status, self._on_update_status)

        self.framework.observe(
            self.on[PeerRelationName].relation_joined, self._on_peer_relation_joined
        )
        self.framework.observe(
            self.on[PeerRelationName].relation_changed, self._on_peer_relation_changed
        )
        self.framework.observe(
            self.on[PeerRelationName].relation_departed, self._on_peer_relation_departed
        )
        self.framework.observe(
            self.on[STORAGE_NAME].storage_detaching, self._on_opensearch_data_storage_detaching
        )

        self.framework.observe(self.on.set_password_action, self._on_set_password_action)
        self.framework.observe(self.on.get_password_action, self._on_get_password_action)

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
            # User config is currently in a default state, which contains multiple insecure default
            # users. Purge the user list before initialising the users the charm requires.
            self._purge_users()
            self._put_admin_user()
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

            for relation in self.model.relations.get(ClientRelationName, []):
                self.opensearch_provider.update_endpoints(relation)

            if data.get(VOTING_TO_DELETE) or data.get(ALLOCS_TO_DELETE):
                self.opensearch_exclusions.cleanup()

        # Run restart node on the concerned unit
        self._reconfigure_and_restart_unit_if_needed()

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

    def _on_opensearch_data_storage_detaching(self, _: StorageDetachingEvent):
        """Triggered when removing unit, Prior to the storage being detached."""
        # we currently block the scale down if majority removed
        if self.app.planned_units() < math.ceil(
            len(self.model.get_relation(PeerRelationName).units) / 2
        ):
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
                raise OpenSearchHAError(NoNodeUpInCluster)

            health = self._apply_cluster_health(wait_for_green_first=True)
            if health == "red":
                raise OpenSearchHAError(ClusterHealthRed)
        finally:
            # release lock
            if self.alt_hosts:
                resp_code = self.opensearch.request(
                    "DELETE",
                    "/.ops_stop",
                    alt_hosts=self.alt_hosts,
                    resp_status_code=True,
                    retries=3,
                )
                # ignore 404, it means the index is not found and this just means that
                # the cleanup happened before but event got deferred because of another error
                if resp_code >= 400 and resp_code != 404:
                    raise OpenSearchHttpError("Failed to remove 'ops_stop' lock index.")

    def _on_update_status(self, event: UpdateStatusEvent):
        """On update status event.

        We want to periodically check for 3 things:
        1- Do we have users that need to be deleted, and if so we need to delete them.
        2- The system requirements are still met
        3- every 6 hours check if certs are expiring soon (in 7 days),
            as a safeguard in case relation broken. As there will be data loss
            without the user noticing in case the cert of the unit transport layer expires.
            So we want to stop opensearch in that case, since it cannot be recovered from.
        """
        # if there are missing system requirements defer
        missing_sys_reqs = self.opensearch.missing_sys_requirements()
        if len(missing_sys_reqs) > 0:
            self.unit.status = BlockedStatus(" - ".join(missing_sys_reqs))
            return

        # if node already shutdown - leave
        if not self.opensearch.is_node_up():
            return

        # if there are exclusions to be removed
        if self.unit.is_leader():
            self.opensearch_exclusions.cleanup()
            self._apply_cluster_health()

        self.user_manager.remove_users_and_roles()

        # If relation broken - leave
        if self.model.get_relation("certificates") is not None:
            return

        # handle when/if certificates are expired
        self._check_certs_expiration(event)

    def _on_set_password_action(self, event: ActionEvent):
        """Set new admin password from user input or generate if not passed."""
        if not self.unit.is_leader():
            event.fail("The action can be run only on leader unit.")
            return

        user_name = event.params.get("username")
        if user_name != "admin":
            event.fail("Only the 'admin' username is allowed for this action.")
            return

        password = event.params.get("password") or generate_password()
        try:
            self._put_admin_user(password)
            password = self.secrets.get(Scope.APP, f"{user_name}_password")
            event.set_results({f"{user_name}-password": password})
        except OpenSearchError as e:
            event.fail(f"Failed changing the password: {e}")

    def _on_get_password_action(self, event: ActionEvent):
        """Return the password and cert chain for the admin user of the cluster."""
        user_name = event.params.get("username")
        if user_name != "admin":
            event.fail("Only the 'admin' username is allowed for this action.")
            return

        if not self._is_tls_fully_configured():
            event.fail("admin user or TLS certificates not configured yet.")
            return

        password = self.secrets.get(Scope.APP, f"{user_name}_password")
        cert = self.secrets.get_object(
            Scope.APP, CertType.APP_ADMIN.val
        )  # replace later with new user certs
        ca_chain = "\n".join(cert["chain"][::-1])

        event.set_results(
            {
                "username": user_name,
                "password": password,
                "ca-chain": ca_chain,
            }
        )

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

    def _start_opensearch(self, event: EventBase) -> None:  # noqa: C901
        """Start OpenSearch, with a generated or passed conf, if all resources configured."""
        if self.opensearch.is_started():
            self._post_start_init()
            self.status.clear(WaitingToStart)
            return

        if not self._can_service_start():
            self.peers_data.delete(Scope.UNIT, "starting")
            event.defer()
            return

        if self.peers_data.get(Scope.UNIT, "starting", False) and self.opensearch.is_failed():
            self.peers_data.delete(Scope.UNIT, "starting")
            event.defer()
            return

        self.unit.status = WaitingStatus(WaitingToStart)

        rel = self.model.get_relation(PeerRelationName)
        for unit in rel.units.union({self.unit}):
            if rel.data[unit].get("starting") == "True":
                event.defer()
                return

        self.peers_data.put(Scope.UNIT, "starting", True)

        try:
            # Retrieve the nodes of the cluster, needed to configure this node
            nodes = self._get_nodes(False)

            # Set the configuration of the node
            self._set_node_conf(nodes)
        except OpenSearchHttpError:
            event.defer()
            self.peers_data.delete(Scope.UNIT, "starting")
            return

        try:
            self.opensearch.start()
            self._post_start_init()
            self.status.clear(WaitingToStart)
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

    def _stop_opensearch(self) -> None:
        """Stop OpenSearch if possible."""
        if not self.opensearch.is_node_up():
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
                self.unit.status = WaitingStatus(ServiceIsStopping)
                return

        self._start_opensearch(event)

    def _can_service_start(self) -> bool:
        """Return if the opensearch service can start."""
        # if there are any missing system requirements leave
        missing_sys_reqs = self.opensearch.missing_sys_requirements()
        if len(missing_sys_reqs) > 0:
            self.unit.status = BlockedStatus(" - ".join(missing_sys_reqs))
            return False

        if self.unit.is_leader():
            return True

        if not self.peers_data.get(Scope.APP, "security_index_initialised", False):
            return False

        if not self.peers_data.get(Scope.APP, "leader_ip"):
            return False

        # When a new unit joins, replica shards are automatically added to it. In order to prevent
        # overloading the cluster, units must be started one at a time. So we defer starting
        # opensearch until all shards in other units are in a "started" or "unassigned" state.
        try:
            busy_shards = ClusterState.busy_shards_by_unit(
                self.opensearch, self.peers_data.get(Scope.APP, "leader_ip")
            )
            if busy_shards:
                message = WaitingForSpecificBusyShards.format(
                    " - ".join([f"{key}/{','.join(val)}" for key, val in busy_shards.items()])
                )
                self.unit.status = WaitingStatus(message)
                return False

            self.status.clear(
                WaitingForSpecificBusyShards, pattern=Status.CheckPattern.Interpolated
            )
        except OpenSearchHttpError:
            # this means that the leader unit is not reachable (not started yet),
            # meaning it's a new cluster, so we can safely start the OpenSearch service
            pass

        return True

    def _purge_users(self):
        """Removes all users from internal_users yaml config.

        This is to be used when starting up the charm, to remove unnecessary default users.
        """
        for user in self.opensearch.config.load("opensearch-security/internal_users.yml").keys():
            if user != "_meta":
                self.opensearch.config.delete("opensearch-security/internal_users.yml", user)

    def _put_admin_user(self, pwd: Optional[str] = None):
        """Change password of Admin user."""
        is_update = pwd is not None
        hashed_pwd, pwd = generate_hashed_password(pwd)

        if is_update:
            # TODO replace with user_manager.patch_user()
            resp = self.opensearch.request(
                "PATCH",
                "/_plugins/_security/api/internalusers/admin",
                [{"op": "replace", "path": "/hash", "value": hashed_pwd}],
            )
            logger.debug(f"Patch admin user response: {resp}")
            if resp.get("status") != "OK":
                raise OpenSearchError(f"{resp}")
        else:
            # reserved: False, prevents this resource from being update-protected from:
            # updates made on the dashboard or the rest api.
            # we grant the admin user all opensearch access + security_rest_api_access
            self.opensearch.config.put(
                "opensearch-security/internal_users.yml",
                "admin",
                {
                    "hash": hashed_pwd,
                    "reserved": False,
                    "backend_roles": ["admin"],
                    "opendistro_security_roles": [
                        "security_rest_api_access",
                        "all_access",
                    ],
                    "description": "Admin user",
                },
            )

        self.secrets.put(Scope.APP, "admin_password", pwd)

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

    def _set_node_conf(self, nodes: List[Node]) -> None:
        """Set the configuration of the current node / unit."""
        # retrieve the updated conf if exists
        update_conf = (self.peers_data.get_object(Scope.APP, "nodes_config") or {}).get(
            self.unit_name
        )
        if update_conf:
            update_conf = Node.from_dict(update_conf)

        # set default generated roles, or the ones passed in the updated conf
        computed_roles = (
            update_conf.roles
            if update_conf
            else ClusterTopology.suggest_roles(nodes, self.app.planned_units())
        )

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

    def _reconfigure_and_restart_unit_if_needed(self):
        """Reconfigure the current unit if a new config was computed for it, then restart."""
        nodes_config = self.peers_data.get_object(Scope.APP, "nodes_config")
        if not nodes_config:
            return

        new_node_conf = nodes_config.get(self.unit_name)
        if not new_node_conf and (
            not self.opensearch.is_node_up() or self.peers_data.get(Scope.UNIT, "starting", False)
        ):
            # the conf could not be computed / broadcasted, because this node is
            # "starting" and is not online "yet" - either barely being configured (i.e. TLS)
            # or waiting to start.
            return

        if not new_node_conf and self.peers_data.get(Scope.UNIT, "starting", False):
            # the conf could not be computed / broadcasted, because this node is
            # "starting" and is not online "yet".
            return

        if new_node_conf:
            new_node_conf = Node.from_dict(new_node_conf)
            current_conf = self.opensearch_config.load_node()
            if sorted(current_conf["node.roles"]) == sorted(new_node_conf.roles):
                # no conf change (roles for now)
                return

        self.unit.status = WaitingStatus(WaitingToStart)
        self.on[self.service_manager.name].acquire_lock.emit(
            callback_override="_restart_opensearch"
        )

    def _compute_and_broadcast_updated_topology(self, current_nodes: Optional[List[Node]]):
        """Compute cluster topology and broadcast node configs (roles for now) to change if any."""
        if not current_nodes:
            return

        updated_nodes = ClusterTopology.recompute_nodes_conf(current_nodes)
        self.peers_data.put_object(Scope.APP, "nodes_config", updated_nodes)

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
        if not self.unit.is_leader():
            # this is needed in case the leader is in an error state and doesn't
            # report the status itself
            self.peers_data.put(Scope.UNIT, "health", status)
            return status

        # cluster health is green
        if status == "green":
            self.status.clear(ClusterHealthRed, app=True)
            self.status.clear(ClusterHealthYellow, app=True)
            return "green"

        # some primary shards are unassigned
        if status == "red":
            self.app.status = BlockedStatus(ClusterHealthRed)
            return "red"

        # some replica shards are unassigned
        shards_by_state = ClusterState.shards_by_state(self.opensearch)
        busy_shards = shards_by_state.get("INITIALIZING", 0) + shards_by_state.get("RELOCATING", 0)
        self.app.status = (
            BlockedStatus(ClusterHealthYellow)
            if busy_shards == 0
            else WaitingStatus(WaitingForBusyShards)
        )
        return "yellow"

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
        return get_host_ip(self, PeerRelationName)

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
        all_units_ips = units_ips(self, PeerRelationName)
        all_hosts = list(all_units_ips.values())
        random.shuffle(all_hosts)

        if not all_hosts:
            return None

        return reachable_hosts([host for host in all_hosts if host != self.unit_ip])
