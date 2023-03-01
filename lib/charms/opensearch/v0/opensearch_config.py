# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Setting configuration in opensearch config files."""
import logging
from typing import Dict, List

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_security import normalized_tls_subject
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution

# The unique Charmhub library identifier, never change it
LIBID = "b02ab02d4fd644fdabe02c61e509093f"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OpenSearchConfig:
    """This class covers the configuration changes depending on certain actions."""

    CONFIG_YML = "opensearch.yml"
    SECURITY_CONFIG_YML = "opensearch-security/config.yml"
    JVM_OPTIONS = "jvm.options"

    def __init__(self, opensearch: OpenSearchDistribution):
        self._opensearch = opensearch

    def load_node(self):
        """Load the opensearch.yml config of the node."""
        return self._opensearch.config.load(self.CONFIG_YML)

    def set_client_auth(self):
        """Configure TLS and basic http for clients."""
        # The security plugin will accept TLS client certs if certs but doesn't require them
        # TODO this may be set to REQUIRED if we want to ensure certs provided by the client app
        self._opensearch.config.put(
            self.CONFIG_YML, "plugins.security.ssl.http.clientauth_mode", "OPTIONAL"
        )

        self._opensearch.config.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/basic_internal_auth_domain/http_enabled",
            True,
        )

        self._opensearch.config.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/clientcert_auth_domain/http_enabled",
            True,
        )

        self._opensearch.config.put(
            self.SECURITY_CONFIG_YML,
            "config/dynamic/authc/clientcert_auth_domain/transport_enabled",
            True,
        )

    def set_admin_tls_conf(self, secrets: Dict[str, any]):
        """Configures the admin certificate."""
        self._opensearch.config.put(
            self.CONFIG_YML,
            "plugins.security.authcz.admin_dn/{}",
            f"{normalized_tls_subject(secrets['subject'])}",
        )

    def set_node_tls_conf(self, cert_type: CertType, secrets: Dict[str, any]):
        """Configures TLS for nodes."""
        logger.debug(f"set_node_tls_conf: {cert_type}")
        target_conf_layer = "http" if cert_type == CertType.UNIT_HTTP else "transport"

        self._opensearch.config.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{target_conf_layer}.pemcert_filepath",
            f"{self._opensearch.paths.certs_relative}/{cert_type}.cert",
        )

        self._opensearch.config.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{target_conf_layer}.pemkey_filepath",
            f"{self._opensearch.paths.certs_relative}/{cert_type}.key",
        )

        self._opensearch.config.put(
            self.CONFIG_YML,
            f"plugins.security.ssl.{target_conf_layer}.pemtrustedcas_filepath",
            f"{self._opensearch.paths.certs_relative}/root-ca.cert",
        )

        key_pwd = secrets.get("key-password")
        if key_pwd is not None:
            self._opensearch.config.put(
                self.CONFIG_YML,
                f"plugins.security.ssl.{target_conf_layer}.pemkey_password",
                key_pwd,
            )

    def append_transport_node(self, ip_pattern_entries: List[str], append: bool = True):
        """Set the IP address of the new unit in nodes_dn."""
        if not append:
            self._opensearch.config.put(
                self.CONFIG_YML,
                "plugins.security.nodes_dn",
                ip_pattern_entries,
            )
            return

        for entry in ip_pattern_entries:
            self._opensearch.config.put(
                self.CONFIG_YML,
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
        contribute_to_bootstrap: bool,
    ) -> None:
        """Set base config for each node in the cluster."""
        self._opensearch.config.put(self.CONFIG_YML, "cluster.name", f"{app_name}-{model_name}")
        self._opensearch.config.put(self.CONFIG_YML, "node.name", unit_name)
        self._opensearch.config.put(
            self.CONFIG_YML, "network.host", ["_site_"] + self._opensearch.network_hosts
        )

        self._opensearch.config.put(self.CONFIG_YML, "node.roles", roles)

        if len(cm_ips) > 0:
            self._opensearch.config.put(self.CONFIG_YML, "discovery.seed_hosts", cm_ips)

        if "cluster_manager" in roles and contribute_to_bootstrap:  # cluster NOT bootstrapped yet
            self._opensearch.config.put(
                self.CONFIG_YML, "cluster.initial_cluster_manager_nodes", cm_names
            )

        self._opensearch.config.put(self.CONFIG_YML, "path.data", self._opensearch.paths.data)
        self._opensearch.config.put(self.CONFIG_YML, "path.logs", self._opensearch.paths.logs)

        self._opensearch.config.replace(
            self.JVM_OPTIONS, "=logs/", f"={self._opensearch.paths.logs}/"
        )

        self._opensearch.config.put(self.CONFIG_YML, "plugins.security.disabled", False)
        self._opensearch.config.put(self.CONFIG_YML, "plugins.security.ssl.http.enabled", True)
        self._opensearch.config.put(
            self.CONFIG_YML, "plugins.security.ssl.transport.enforce_hostname_verification", True
        )

        # security plugin rest API access
        self._opensearch.config.put(
            self.CONFIG_YML,
            "plugins.security.restapi.roles_enabled",
            ["all_access", "security_rest_api_access"],
        )
        # to use the PUT and PATCH methods of the security rest API
        self._opensearch.config.put(
            self.CONFIG_YML,
            "plugins.security.unsupported.restapi.allow_securityconfig_modification",
            True,
        )

    def cleanup_bootstrap_conf(self):
        """Remove some conf entries when the cluster is bootstrapped."""
        self._opensearch.config.delete(self.CONFIG_YML, "cluster.initial_cluster_manager_nodes")
