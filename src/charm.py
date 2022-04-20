#!/usr/bin/env python3
"""Charm code for OpenSearch service."""
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import grp
import logging
import os
import pwd
import socket
from pathlib import Path
from subprocess import CalledProcessError, check_call, check_output
from typing import Any, Dict, List, Optional, Tuple

import requests
from charms.operator_libs_linux.v1.systemd import daemon_reload, service_restart
from jinja2 import Environment, FileSystemLoader
from ops.charm import CharmBase, LeaderElectedEvent, RelationEvent, RelationJoinedEvent
from ops.framework import StoredState
from ops.main import main
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    MaintenanceStatus,
    ModelError,
    Relation,
)
from requests.exceptions import HTTPError

logger = logging.getLogger(__name__)

PEER = "opensearch"
TLS = "certificates"
CCR_CONNECTION = "ccr-connection-alias"

SNAP_NAME = "opensearch"
SNAP_COMMON_DIR = f"/var/snap/{SNAP_NAME}/common"
CONFIG_PATH = Path(SNAP_COMMON_DIR) / "config"

CONFIG_MAP = {
    "jvm.options": {"cmd": None, "config_path": CONFIG_PATH, "chmod": 0o660},
    "sysctl.conf": {"cmd": "sysctl -p", "config_path": Path("/etc"), "chmod": 0o644},
    "opensearch.yml": {"cmd": None, "config_path": CONFIG_PATH, "chmod": 0o660},
}


class OpenSearchCharm(CharmBase):
    """Charm the service."""

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.opensearch_relation_changed, self._opensearch_relation_changed
        )
        self.framework.observe(self.on.client_relation_joined, self._client_relation_handler)
        self.framework.observe(self.on.client_relation_changed, self._client_relation_handler)
        self.framework.observe(
            self.on.ccr_leader_relation_joined,
            self._on_config_changed,
        )
        self.framework.observe(
            self.on.ccr_leader_relation_changed,
            self._on_config_changed,
        )
        self.framework.observe(
            self.on.ccr_follower_relation_changed,
            self._ccr_follower_relation_changed,
        )

    @property
    def _ca_cert(self) -> Path:
        """Get the root CA certificate path.

        Returns:
            Path: path of root CA file on opensearch config.
        """
        return CONFIG_PATH / "root-ca.pem"

    @property
    def _admin_cert(self) -> Path:
        """Get the admin client certificate path.

        Returns:
            Path: path of admin client certificate file on opensearch
            config.
        """
        return CONFIG_PATH / "admin.pem"

    @property
    def _admin_key(self) -> Path:
        """Get the admin private key path.

        Returns:
            Path: path of admin private key file on opensearch config.
        """
        return CONFIG_PATH / "admin-key.pem"

    @property
    def _admin_cert_requests(self) -> Tuple[str, str]:
        """Get the certificate to be used on requests python lib.

        With admin cert is possible to use Opensearch API with privileges,
        using encryption in the requests.

        Returns:
            Tuple[str, str]: tuple containing the string path to admin
            client certificate and admin private key.
        """
        return (str(self._admin_cert), str(self._admin_key))

    @property
    def _peers(self) -> Optional[Relation]:
        """Fetch the peer relation.

        Returns:
            Optional[Relation]: An `ops.model.Relation` object representing the peer
                relation.
        """
        return self.model.get_relation(PEER)

    @property
    def _unit_ips(self) -> List[str]:
        """Retrieve IP addresses associated with OpenSearch peers units.

        Returns:
            List[str]: a list of private-address from OpenSearch node units.
        """
        addresses = [
            str(self._peers.data[unit].get("private-address")) for unit in self._peers.units
        ]
        self_address = self._unit_ip
        addresses.append(self_address)
        return addresses

    @property
    def _unit_ip(self) -> str:
        """Retrieve IP addresses associated with OpenSearch unit.

        Returns:
            str: IP address of the unit
        """
        return str(self.model.get_binding(PEER).network.bind_address)

    @property
    def _unit_name(self) -> str:
        """Get the unit name changing "/" to "-".

        The modified unit name is used on files names that contain certs and
        private keys. Ex: Unit openserarch/0 becomes opensearch-0 and
        generate opensearch-0.pem and opensearch-0-key.pem.

        Returns:
            str: unit name changed
        """
        return self.unit.name.replace("/", "-")

    @property
    def _admin_dn(self) -> str:
        """Get the distinguished name from admin cert.

        Returns:
            str: DN containing the fields CN, OU, O, L, ST and C
        """
        admin_cert = CONFIG_PATH / "admin.pem"
        return self._get_dn(admin_cert)

    @property
    def _node_dn(self) -> str:
        """Get the distinguished name from node cert.

        Returns:
            str: DN containing the fields CN, OU, O, L, ST and C
        """
        node = CONFIG_PATH / f"{self._unit_name}.pem"
        node_dn = self._get_dn(node)
        # share node DN with peers
        if node_dn:
            self._peers.data[self.unit].update({"dn": node_dn})
        return node_dn

    def _get_dn(self, cert_path: Path) -> str:
        """Get the distinguished name from a cert file.

        Args:
            cert_path (Path): path from cert file.

        Returns:
            str: DN containing the fields CN, OU, O, L, ST and C
        """
        if cert_path.exists():
            try:
                logger.info("Getting DN from file %s", cert_path)
                dn = (
                    check_output(
                        f"openssl x509 -subject -nameopt RFC2253 -noout -in {cert_path}".split()
                    )
                    .decode("ascii")
                    .rstrip()
                )
                return dn.replace("subject=", "")
            except CalledProcessError as e:
                logger.exception("Failed to run command %s: %s", e.cmd, e)
                raise
        return None

    @property
    def _nodes_dn(self) -> List[str]:
        """Retrieve distinguished names (DN) associated with OpenSearch nodes.

        Returns:
            List[str]: a list of DN from all nodes in the peer relation.
        """
        nodes_dn = [str(self._peers.data[unit].get("dn")) for unit in self._peers.units]
        self_dn = self._node_dn
        nodes_dn.append(self_dn)
        nodes_dn.sort()
        return nodes_dn

    @property
    def _followers_dn(self) -> List[str]:
        """Retrieve distinguished names (DN) associated with OpenSearch follower nodes.

        Returns:
            List[str]: a list of DN from all nodes in the ccr_leader relation.
        """
        ccr_leader_relation = self.model.get_relation("ccr_leader")
        followers_dn = []
        if ccr_leader_relation:
            followers_dn = [
                str(ccr_leader_relation.data[unit].get("dn")) for unit in ccr_leader_relation.units
            ]
            followers_dn.sort()
        return followers_dn

    @property
    def _master_node(self) -> List[str]:
        """Retrieve all initial master nodes on the cluster.

        Returns:
            List[str]: a list of nodes names that can start as master.
        """
        # TODO(gabrielcocenza): if nodes has specific roles (data, ingest, coordinating),
        # this logic might need to change.
        return [self._peers.data[self.app].get("master_node")]

    def _get_context(self) -> Dict[str, Any]:
        """Get variables context necessary to render configuration templates.

        Returns:
            Dict[str, Any]: Dictionary containing the variables to be used on
            jinja2 templates
        """
        context = dict(self.model.config)
        context["unit_ips"] = self._unit_ips
        context["network_host"] = self._unit_ip
        context["node_name"] = socket.getfqdn()
        context["host_name"] = socket.gethostname()
        context["node_cert"] = f"{self._unit_name}.pem"
        context["node_key"] = f"{self._unit_name}-key.pem"
        context["admin_dn"] = self._admin_dn
        context["ca"] = "root-ca.pem"
        context["nodes_dn"] = self._nodes_dn
        context["master_node"] = self._master_node
        context["followers_dn"] = self._followers_dn

        return context

    def _on_install(self, _):
        """Installation hook that installs OpenSearch."""
        self.unit.status = MaintenanceStatus("Installing OpenSearch")
        # TODO(gabrielcocenza): change to snap lib as soon the snap store is available.
        # Right now there is a open request to auto-connect mount-observe and system-files at
        # https://forum.snapcraft.io/t/manual-review-for-opensearch-auto-connect-request-for-mount-observe-and-system-files/29475
        # A PR to include max_map_count into system-observe interface was approved in systemd
        # https://github.com/snapcore/snapd/pull/11656 and might be available soon in a stable
        # release. max-map-count interface using system-files should change to use system-observe.
        snap_file = self.model.resources.fetch("opensearch")
        check_call(["snap", "install", "--dangerous", snap_file])
        # TODO(gabrielcocenza): remove manual connection after snap team vote approval
        for interface in ["mount-observe", "max-map-count", "systemd-opensearch"]:
            check_call(["snap", "connect", f"opensearch:{interface}"])
        # daemon-reload to be sure that override.conf for opensearch is set
        daemon_reload()
        self.unit.status = MaintenanceStatus("Waiting for certificates")

    def _on_leader_elected(self, event: LeaderElectedEvent) -> None:
        logging.info("Initial master node %s selected", socket.getfqdn())
        self._peers.data[self.app].update({"master_node": socket.getfqdn()})

    def _on_config_changed(self, _):
        """Render templates for configuration."""
        self._configure_security()
        context = self._get_context()
        for template in CONFIG_MAP.keys():
            config_path = CONFIG_MAP[template].get("config_path")
            cmd = CONFIG_MAP[template].get("cmd")
            chmod = CONFIG_MAP[template].get("chmod")
            self._write_config(config_path, template, context, chmod)
            if cmd:
                try:
                    check_call(cmd.split())
                except CalledProcessError as e:
                    logger.exception("Failed to run command %s: %s", e.cmd, e)
                    raise

        # update client relation data
        client_relation = self.model.get_relation("client")
        if client_relation:
            logger.info("Updating client relation data.")
            client_relation.data[self.unit].update(
                {
                    "cluster_name": self.model.config.get("cluster_name"),
                    "port": "9200",
                }
            )
        daemon_reload()
        service_restart("snap.opensearch.daemon.service")

    def _write_config(
        self,
        config_path: Path,
        template: str,
        context: Dict[str, Any],
        chmod: int,
        templates_folder: str = "templates",
    ) -> None:
        """Render and write jinja2 templates for Opensearch configuration.

        Args:
            config_path (Path): path for the config file.
            template (str): template name.
            context (Dict[str, Any]): variables to render on templates.
            chmod (int): chmod of the file.
            templates_folder (str, optional): Path to the folder that has the templates.
                Defaults to "templates".
        """
        target = config_path / template
        rendered_template = Environment(
            loader=FileSystemLoader(templates_folder), trim_blocks=True, lstrip_blocks=True
        ).get_template(template)
        target.write_text(rendered_template.render(context))
        target.chmod(chmod)

    def _opensearch_relation_changed(self, event: RelationEvent) -> None:
        """Add unit to the cluster by configuring the file opensearch.yml.

        Args:
            event (RelationEvent): The triggering relation changed event.
        """
        self._configure_security()
        context = self._get_context()
        config_path = CONFIG_MAP["opensearch.yml"].get("config_path")
        chmod = CONFIG_MAP["opensearch.yml"].get("chmod")
        self._write_config(config_path, "opensearch.yml", context, chmod)
        daemon_reload()
        service_restart("snap.opensearch.daemon.service")

    def _client_relation_handler(self, event: RelationJoinedEvent) -> None:
        """Set the cluster name and port through the relation.

        Args:
            event (RelationJoinedEvent): The triggering relation joined event.
        """
        event.relation.data[self.unit].update(
            {
                "cluster_name": self.model.config.get("cluster_name"),
                "port": "9200",
            }
        )

    def _configure_security(self):
        """Configure the security plugin.

        Please consult the documentation for further information on the
        security plugin https://opensearch.org/docs/latest/security-plugin/index/
        """
        certificates = self.model.get_relation(TLS)

        if certificates:
            # TODO(gabrielcocenza) insert the logic when the charm relates
            # with a CA (Vault, EasyRsa)
            return
        else:
            self._configure_self_signed_cert()

    def _allocate_resources(self) -> bool:
        """Allocate resources in the config folder to generate node certificates."""
        resources = ["tls_ca", "tls_key", "admin_key", "admin_cert", "open_ssl_conf"]
        try:
            resources_path = [self.model.resources.fetch(resource) for resource in resources]
        except ModelError as e:
            self.unit.status = BlockedStatus("Something went wrong when claiming resources")
            logger.error("Something went wrong when claiming resources: %s", e)
            raise

        # copy the files to the config path
        for resource_path in resources_path:
            # check if resources files are empty
            if not resource_path.stat().st_size:
                msg = (
                    f"File {resource_path.name} is empty. "
                    f"Check README on how to create self-signed certificates"
                )
                self.unit.status = BlockedStatus(msg)
                logger.warning("%s", msg)
                raise ResourceWarning

            target = CONFIG_PATH / resource_path.name
            target.write_text(resource_path.open().read())
            # change ownership for snap_daemon. OpenSearch can't run as root.
            os.chown(
                str(target), pwd.getpwnam("snap_daemon").pw_uid, grp.getgrnam("snap_daemon").gr_gid
            )

    def _configure_self_signed_cert(self):
        """Configure self signed certificates.

        Please consult the documentation for further information:
        https://opensearch.org/docs/latest/security-plugin/configuration/generate-certificates/
        """
        node_key = CONFIG_PATH / f"{self._unit_name}-key.pem"
        node_cert = CONFIG_PATH / f"{self._unit_name}.pem"

        # if private key and cert exists, the security is already configured
        if node_key.exists() and node_cert.exists():
            logger.info("Private key and cert already created on %s.", self.unit.name)
            return

        self._allocate_resources()

        # render openssl.conf for node certificate
        self._write_config(CONFIG_PATH, "openssl.conf", self._get_context(), 0o660, CONFIG_PATH)

        # generate node certificate and private key
        file_prefix = CONFIG_PATH / self._unit_name
        openssl_config = CONFIG_PATH / "openssl.conf"
        logger.info("Creating private key and cert for %s", self.unit.name)
        try:
            check_call(f"openssl genrsa -out {file_prefix}-temp.pem 2048".split())
            check_call(
                (
                    f"openssl pkcs8 -inform PEM -outform PEM -in {file_prefix}-temp.pem -topk8 "
                    f"-nocrypt -v1 PBE-SHA1-3DES -out {node_key}"
                ).split()
            )
            check_call(
                (
                    f"openssl req -new -key {node_key} -config {openssl_config} "
                    f"-out {file_prefix}.csr"
                ).split()
            )
            check_call(
                (
                    f"openssl x509 -req -in {file_prefix}.csr -CA {CONFIG_PATH}/root-ca.pem -CAkey "
                    f"{CONFIG_PATH}/root-ca-key.pem -CAcreateserial -sha256 -out {node_cert} -days 730 "
                    f"-extfile {openssl_config} -extensions v3_req"
                ).split()
            )

        except CalledProcessError as e:
            logger.exception("Failed to run command %s: %s", e.cmd, e)
            raise
        except FileNotFoundError as e:
            logger.exception("FileNotFoundError: %s", e)
            raise

        # change ownership of node certificates
        for target in [node_key, node_cert]:
            os.chown(
                str(target), pwd.getpwnam("snap_daemon").pw_uid, grp.getgrnam("snap_daemon").gr_gid
            )

        # remove temp key and csr
        files_to_remove = [f"{file_prefix}-temp.pem", f"{file_prefix}.csr"]
        logger.info("Removing temp key and csr file from %s", self.unit.name)
        for file in files_to_remove:
            Path(file).unlink()

        # run security plugin to configure certificates
        self._run_security_plugin()

    def _run_security_plugin(self) -> None:
        """Run the Security Plugin."""
        try:
            check_call(["opensearch.security"])
            daemon_reload()
            service_restart("snap.opensearch.daemon.service")
            self.unit.status = ActiveStatus("OpenSearch running")
        except CalledProcessError as e:
            logger.exception("Failed to run command %s: %s", e.cmd, e)
            raise

    def _ccr_follower_relation_changed(self, event: RelationEvent) -> None:
        """Set the configuration for Cross Cluster Configuration (CCR) on follower side.

        Most changes occur on the follower cluster, not the leader cluster. Just the
        leader of follower cluster sets the configuration for CCR and non-leader share
        the CN to update opensearch configuration on the leader cluster units.
        All indexes from the leader cluster are replicated with the auto-follow pattern
        set to "*".
        Please consult the documentation for further information:
        * https://opensearch.org/docs/latest/replication-plugin/index/
        * https://opensearch.org/docs/latest/replication-plugin/get-started/
        * https://opensearch.org/docs/latest/replication-plugin/auto-follow/

        Args:
            event (RelationEvent): The triggering relation event.
        """
        # Share the CN with the leader cluster to add in the configuration file
        follower_dn = self._node_dn
        logger.info("Sharing DN follower: %s", follower_dn)
        event.relation.data[self.unit]["dn"] = follower_dn
        ccr_follower_relation = self.model.get_relation("ccr_follower")

        if not self.unit.is_leader():
            return

        if not ccr_follower_relation.units:
            logger.debug("CCR not ready to start.")
            event.defer()
            self.unit.status = MaintenanceStatus("Waiting for CCR to get ready")
            return

        leader_ips = [
            f"{ccr_follower_relation.data[unit].get('private-address')}:9300"
            for unit in ccr_follower_relation.units
        ]

        # Set up a cross-cluster connection

        # NOTE(gabrielcocenza) the ideal approach would be using the opensearch-py python client,
        # to be agnostic with changes on future versions that can break the request. So far it
        # it doesn't has the feature needed for CCR. I've opened a feature
        # request in the project: https://github.com/opensearch-project/opensearch-py/issues/143

        data = {"persistent": {"cluster": {"remote": {CCR_CONNECTION: {"seeds": leader_ips}}}}}
        try:
            resp = requests.put(
                "https://localhost:9200/_cluster/settings?pretty",
                json=data,
                cert=self._admin_cert_requests,
                verify=self._ca_cert,
            )
            logger.debug("response for set up CCR connection: %s", resp.text)
            resp.raise_for_status()
        except HTTPError as e:
            logger.exception("Failed to create a CCR connection: %s", e)
            raise
        except socket.error as e:
            logger.debug("CCR not ready yet with socket error: %s", e)
            event.defer()
            self.unit.status = MaintenanceStatus("Waiting for CCR to get ready")
            return

        # set auto-follow to all indexes on the leader cluster
        data = {
            "leader_alias": CCR_CONNECTION,
            "name": "all-replication-rule",
            "pattern": "*",
            "use_roles": {
                "leader_cluster_role": "all_access",
                "follower_cluster_role": "all_access",
            },
        }

        try:
            resp = requests.post(
                "https://localhost:9200/_plugins/_replication/_autofollow?pretty",
                json=data,
                cert=self._admin_cert_requests,
                verify=self._ca_cert,
            )
            logger.debug("response for set up CCR auto-follow: %s", resp.text)
            resp.raise_for_status()
            self.app.status = ActiveStatus("CCR running")
            self.unit.status = ActiveStatus("OpenSearch running")
        except HTTPError as e:
            if resp.status_code == 500:
                logger.debug("CCR not ready yet: %s", e)
                self.unit.status = MaintenanceStatus("Waiting for CCR to get ready")
                event.defer()
                return
            logger.exception("Failed to create a CCR auto-follow: %s", e)
            raise


if __name__ == "__main__":
    main(OpenSearchCharm)
