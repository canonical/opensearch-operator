# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Setting configuration in opensearch config files."""
import logging
import socket
from typing import Any, Dict, List

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

        # This allows the new CMs to be discovered automatically (hot reload of unicast_hosts.txt)
        self._opensearch.config.put(self.CONFIG_YML, "discovery.seed_providers", "file")
        self.add_seed_hosts(cm_ips)

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

    def add_seed_hosts(self, cm_ips: List[str]):
        """Add CM nodes ips / host names to the seed host list of this unit."""
        cm_ips_hostnames = set(cm_ips)
        for ip in cm_ips:
            try:
                name, aliases, addresses = socket.gethostbyaddr(ip)
                cm_ips_hostnames.update([name] + aliases + addresses)
            except socket.herror:
                # no ptr record - the IP is enough and the only thing we have
                pass

        with open(self._opensearch.paths.seed_hosts, "w+") as f:
            lines = "\n".join([entry for entry in cm_ips_hostnames if entry.strip()])
            f.write(f"{lines}\n")

    def cleanup_bootstrap_conf(self):
        """Remove some conf entries when the cluster is bootstrapped."""
        self._opensearch.config.delete(self.CONFIG_YML, "cluster.initial_cluster_manager_nodes")

    def get_plugin(self, plugin_config: Dict[str, str]) -> Dict[str, Any]:
        """Gets a list of configurations from opensearch.yml."""
        result = {}
        loaded_configs = self.load_node()
        for key in plugin_config.keys():
            result[key] = loaded_configs.get(key, None)
        return result

    def add_plugin(self, plugin_config: Dict[str, str]) -> None:
        """Adds a plugin configurations into opensearch.yml."""
        for key, val in plugin_config.items():
            self._opensearch.config.put(self.CONFIG_YML, key, val)

    def delete_plugin(self, plugin_config: Dict[str, str]) -> None:
        """Adds a plugin configurations into opensearch.yml."""
        for key, val in plugin_config.items():
            self._opensearch.config.delete(self.CONFIG_YML, key, val)

    def update_host_if_needed(self) -> bool:
        """Update the opensearch config with the current network hosts, after having started.

        Returns: True if host updated, False otherwise.
        """
        old_hosts = set(self.load_node().get("network.host", []))
        if not old_hosts:
            # Unit not configured yet
            return False

        hosts = set(["_site_"] + self._opensearch.network_hosts)
        if old_hosts != hosts:
            logger.info(f"Updating network.host from: {old_hosts} - to: {hosts}")
            self._opensearch.config.put(self.CONFIG_YML, "network.host", hosts)
            return True

        return False
