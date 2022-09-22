#!/usr/bin/env python3

# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""
import logging
from typing import Optional, List

from ops.charm import (
    ActionEvent,
    InstallEvent,
    LeaderElectedEvent, RelationJoinedEvent,
)
from ops.framework import StoredState
from ops.main import main
from ops.model import MaintenanceStatus, BlockedStatus, ActiveStatus

from charms.opensearch.v0.helpers.charms import Scope
from charms.opensearch.v0.helpers.security import generate_hashed_password
from charms.opensearch.v0.opensearch_base_charm import PEER, OpenSearchBaseCharm
from charms.opensearch.v0.opensearch_distro import OpenSearchInstallError, OpenSearchHttpError
from charms.opensearch.v0.opensearch_tls import CertType
from opensearch import OpenSearchSnap

logger = logging.getLogger(__name__)


class OpenSearchOperatorCharm(OpenSearchBaseCharm):
    """This class represents the machine charm for OpenSearch."""

    _stored = StoredState()

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
        """Triggered when a new peer relation is established."""
        pass

    def _on_put_client(self, event: ActionEvent):
        # need to create users / roles
        cert_cn = event.params.get("cn")
        roles = event.params.get("roles").split(",")

        try:
            self._add_update_client(cert_cn, roles)
        except OpenSearchHttpError:
            event.defer()

    def _on_delete_client(self, event: ActionEvent):
        # need to create users / roles
        cert_cn = event.params.get("cn")
        try:
            self._delete_client(cert_cn)
        except OpenSearchHttpError:
            event.defer()

    def on_tls_conf_set(self, scope: Scope, cert_type: CertType, secret_key_prefix: str, renewal: bool):
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
        path_prefix = f"{self.opensearch.path_certs}/{secret_key_prefix}"
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

    def _initialize_admin_user(self):
        hashed_pwd, pwd = generate_hashed_password()
        self.secrets.put(Scope.APP, "admin_password", pwd)

        config_path = f"{self.opensearch.path_plugins}/config/internal_users.yml"
        self.opensearch.config.put(
            config_path,
            "admin",
            {
                "hash": hashed_pwd,
                "reserved": "true",
                "backend_roles": ["admin"],
                "description": "Admin user"
            })

    def _require_client_tls_auth(self):
        self.opensearch.config.put(
            "opensearch.yml",
            "plugins.security.ssl.http.clientauth_mode",
            "REQUIRE"
        )

        self.opensearch.config.put(
            f"{self.opensearch.path_conf}/opensearch-security/config.yml",
            "config/dynamic/authc/clientcert_auth_domain/http_enabled",
            "true"
        )

        self.opensearch.config.put(
            f"{self.opensearch.path_conf}/opensearch-security/config.yml",
            "config/dynamic/authc/clientcert_auth_domain/transport_enabled",
            "true"
        )

    def _initialize_security_index(self, admin_key_password: Optional[str]):
        args = [
            f"-cd {self.opensearch.path_conf}/opensearch-security/",
            "-icl",
            "-nhnv",
            f"-cacert {self.opensearch.path_certs}/root-ca.pem",
            f"-cert {self.opensearch.path_certs}/admin.pem",
            f"-key {self.opensearch.path_certs}/admin-key.pem",
        ]

        if admin_key_password is not None:
            args.append(f"keypass {admin_key_password}")

        self.opensearch.run_script("plugins/opensearch-security/tools/securityadmin.sh", " ".join(args))

    def _add_update_client(self, cert_cn: str, roles: List[str]) -> None:
        # TODO: create user ?

        resp = self.opensearch.request(
            "PUT",
            "/_plugins/_security/api/rolesmapping/",
            {
                "backend_roles": roles,
                "hosts": [self.opensearch.host],
                "users": [cert_cn]
            }
        )

        logger.debug(resp)

    def _delete_client(self, cert_cn: str) -> None:
        # TODO delete user ?
        resp = self.opensearch.request(
            "DELETE",
            "/_plugins/_security/api/rolesmapping/"
        )

        logger.debug(resp)

    def _write_admin_tls_conf(self, subject: str):
        target_conf_file = "opensearch.yml"

        # TODO: for now it's okay since only CN on subj,
        # but make sure to format the subject as per RFC2253 (inverted)
        self.opensearch.config.put(
            target_conf_file,
            "plugins.security.authcz.admin_dn/[]",
            subject
        )

    def _write_node_tls_conf(self, cert_type: CertType, subject: str, key_pwd: Optional[str], path_prefix: str):
        target_conf_file = "opensearch.yml"
        target_conf_layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"

        self.opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemcert_filepath",
            f"{path_prefix}.cert"
        )

        self.opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemkey_filepath",
            f"{path_prefix}.key"
        )

        if key_pwd is not None:
            self.opensearch.config.put(
                target_conf_file,
                f"plugins.security.ssl.{target_conf_layer}.pemkey_password",
                key_pwd
            )

        # TODO: for now it's okay since only CN on subj,
        # but make sure to format the subject as per RFC2253 (inverted)
        self.opensearch.config.put(
            target_conf_file,
            "plugins.security.nodes_dn/[]",
            subject
        )


if __name__ == "__main__":
    main(OpenSearchOperatorCharm)
