# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Setting configuration in opensearch config files."""
import logging
from typing import Dict, List

from charms.opensearch.v0.helpers.security import normalized_tls_subject
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.tls_constants import CertType

# The unique Charmhub library identifier, never change it
LIBID = "f4bd9c1dad554f9ea52954b8181cdc19"
LIBAPI = 0
LIBPATCH = 0

logger = logging.getLogger(__name__)


class OpenSearchConfig:
    """This class covers the configuration changes depending on certain actions."""

    def __init__(self, opensearch: OpenSearchDistribution):
        self._opensearch = opensearch

    def set_client_auth(self):
        """Configure TLS and basic http for clients."""
        # The security plugin will accept TLS client certs if certs but doesn't require them
        self._opensearch.config.put(
            "opensearch.yml", "plugins.security.ssl.http.clientauth_mode", "OPTIONAL"
        )

        security_config_file = "opensearch-security/config.yml"

        self._opensearch.config.put(
            security_config_file,
            "config/dynamic/authc/basic_internal_auth_domain/http_enabled",
            True,
        )

        self._opensearch.config.put(
            security_config_file,
            "config/dynamic/authc/clientcert_auth_domain/http_enabled",
            True,
        )

        self._opensearch.config.put(
            security_config_file,
            "config/dynamic/authc/clientcert_auth_domain/transport_enabled",
            True,
        )

    def set_admin_tls_conf(self, secrets: Dict[str, any]):
        """Configures the admin certificate."""
        target_conf_file = "opensearch.yml"

        self._opensearch.config.put(
            target_conf_file,
            "plugins.security.authcz.admin_dn/{}",
            f"{normalized_tls_subject(secrets['subject'])}",
        )

    def set_node_tls_conf(self, cert_type: CertType, secrets: Dict[str, any]):
        """Configures TLS for nodes."""
        logger.debug(f"set_node_tls_conf: {cert_type}")
        target_conf_file = "opensearch.yml"
        target_conf_layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"

        self._opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemcert_filepath",
            f"{self._opensearch.paths.certs_relative}/{cert_type.val}.cert",
        )

        self._opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemkey_filepath",
            f"{self._opensearch.paths.certs_relative}/{cert_type.val}.key",
        )

        self._opensearch.config.put(
            target_conf_file,
            f"plugins.security.ssl.{target_conf_layer}.pemtrustedcas_filepath",
            f"{self._opensearch.paths.certs_relative}/root-ca.cert",
        )

        key_pwd = secrets.get("key-password")
        if key_pwd is not None:
            self._opensearch.config.put(
                target_conf_file,
                f"plugins.security.ssl.{target_conf_layer}.pemkey_password",
                key_pwd,
            )

    def append_transport_node(self, ip_pattern_entries: List[str], append: bool = True):
        """Set the IP address of the new unit in nodes_dn."""
        if not append:
            self._opensearch.config.put(
                "opensearch.yml",
                "plugins.security.nodes_dn",
                ip_pattern_entries,
            )
            return

        for entry in ip_pattern_entries:
            self._opensearch.config.put(
                "opensearch.yml",
                "plugins.security.nodes_dn/{}",
                entry,
            )

    def set_node(
        self,
        app_name: str,
        model_name: str,
        unit_name: str,
        roles: List[str],
        cm_names: List[str],
        cm_ips: List[str],
    ) -> None:
        """Set base config for each node in the cluster."""
        target_conf_file = "opensearch.yml"

        self._opensearch.config.put(target_conf_file, "cluster.name", f"{app_name}-{model_name}")
        self._opensearch.config.put(target_conf_file, "node.name", unit_name)
        self._opensearch.config.put(
            target_conf_file, "network.host", ["_local_", self._opensearch.host]
        )

        self._opensearch.config.put(target_conf_file, "node.roles", roles)

        if len(cm_ips) > 0:
            self._opensearch.config.put(target_conf_file, "discovery.seed_hosts", cm_ips)

        if "cluster_manager" in roles and len(cm_ips) < 2:  # cluster NOT bootstrapped yet
            self._opensearch.config.put(
                target_conf_file, "cluster.initial_cluster_manager_nodes", cm_names
            )

        self._opensearch.config.put(target_conf_file, "path.data", self._opensearch.paths.data)
        self._opensearch.config.put(target_conf_file, "path.logs", self._opensearch.paths.logs)

        self._opensearch.config.replace(
            "jvm.options", "=logs/", f"={self._opensearch.paths.logs}/"
        )

        self._opensearch.config.put(target_conf_file, "plugins.security.disabled", False)
        self._opensearch.config.put(target_conf_file, "plugins.security.ssl.http.enabled", True)
        self._opensearch.config.put(
            target_conf_file, "plugins.security.ssl.transport.enforce_hostname_verification", True
        )

    def cleanup_conf_if_bootstrapped(self):
        """Remove some conf entries when the cluster is bootstrapped."""
        self._opensearch.config.delete("opensearch.yml", "cluster.initial_cluster_manager_nodes")
