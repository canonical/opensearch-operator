# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Setting configuration in opensearch config files."""
import json
import logging
import socket
import subprocess
from typing import Any, Dict, List, Optional

from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.helper_enums import ByteUnit
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


class OpenSearchPerformanceProfile:
    """Applies the performance profile to the opensearch config."""

    def __init__(self):
        self._jvm_options = {}
        self._opensearch_yml = {}

    def _meminfo(self) -> dict[str, Any]:
        with open("/proc/meminfo") as f:
            meminfo = f.read()
        return {
            line.split()[0][:-1].lower(): ByteUnit.to_kb(
                (
                    line.split()[1],
                    line.split()[2],
                )
            )
            for line in meminfo.split("\n")
            if line
        }

    def _cpuinfo(self) -> dict[str, Any]:
        return json.loads(subprocess.check_output(["cpuinfo", "--json"]))

    def _java_heap(self) -> dict[str, str]:
        """Calculate the java heap size."""
        raise NotImplementedError

    @property
    def jvm_options(self):
        """Get the jvm options."""
        return self._jvm_options

    @jvm_options.setter
    def jvm_options(self, jvm_options: Dict[str, str]):
        """Set the jvm options."""
        self._jvm_options = jvm_options

    @property
    def opensearch_yml(self):
        """Get the opensearch yml options."""
        return self._opensearch_yml

    @opensearch_yml.setter
    def opensearch_yml(self, opensearch_yml: Dict[str, str]):
        """Set the opensearch yml options."""
        self._opensearch_yml = opensearch_yml


class HighPerformanceProfile(OpenSearchPerformanceProfile):
    """High performance profile for opensearch."""

    @property
    def jvm_options(self):
        """Get the jvm options."""
        self._jvm_options |= self._calculate_memory()
        return self._jvm_options

    @property
    def opensearch_yml(self):
        """Set the opensearch yml options."""
        meminfo = self._meminfo()
        total_memory, _ = meminfo["memtotal"]  # we know it is in kB
        flush_threshold_size = ByteUnit.format(total_memory // 4)

        return self._opensearch_yml | {
            "index.translog.flush_threshold_size": f"{flush_threshold_size[0]}{str(flush_threshold_size[1]).upper()}",
            "index.merge.scheduler.max_thread_count": max(self._cpuinfo()["count"], 4),
            "index.merge.scheduler.max_merge_count": max(self._cpuinfo()["count"], 4),
            "index.codec": "zstd",
        }

    def _calculate_memory(self) -> str:
        """Calculate the memory for the high performance profile."""
        meminfo = self._meminfo()
        total_memory, _ = meminfo["memtotal"]  # we know it is in kB
        jvm_memory, unit = ByteUnit.format(total_memory // 2)
        return {
            "Xms": f"{jvm_memory}{str(unit)[0]}",
            "Xmx": f"{jvm_memory}{str(unit)[0]}",
        }


class OpenSearchConfig:
    """This class covers the configuration changes depending on certain actions."""

    CONFIG_YML = "opensearch.yml"
    SECURITY_CONFIG_YML = "opensearch-security/config.yml"
    JVM_OPTIONS = "jvm.options"

    def __init__(self, opensearch: OpenSearchDistribution):
        self._opensearch = opensearch

    def set_profile(self, profile: str) -> None:
        """Adds plugin configuration to opensearch.yml."""
        configs = None
        # TODO: create an actual list to track the different profiles.
        if profile == "production":
            configs = HighPerformanceProfile()
        for key, val in configs.opensearch_yml.items():
            self._opensearch.config.put(self.CONFIG_YML, key, val)
        for key, val in configs.jvm_options.items():
            self._opensearch.config.put(self.JVM_OPTIONS, key, val)

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
        cluster_name: str,
        unit_name: str,
        roles: List[str],
        cm_names: List[str],
        cm_ips: List[str],
        contribute_to_bootstrap: bool,
        node_temperature: Optional[str] = None,
    ) -> None:
        """Set base config for each node in the cluster."""
        self._opensearch.config.put(self.CONFIG_YML, "cluster.name", f"{cluster_name}")
        self._opensearch.config.put(self.CONFIG_YML, "node.name", unit_name)
        self._opensearch.config.put(
            self.CONFIG_YML, "network.host", ["_site_"] + self._opensearch.network_hosts
        )

        self._opensearch.config.put(self.CONFIG_YML, "node.roles", roles)
        if node_temperature:
            self._opensearch.config.put(self.CONFIG_YML, "node.attr.temp", node_temperature)
        else:
            self._opensearch.config.delete(self.CONFIG_YML, "node.attr.temp")

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

    def remove_temporary_data_role(self):
        """Remove the data role that was added temporarily to the first dedicated CM node."""
        conf = self._opensearch.config.load(self.CONFIG_YML)
        stored_roles = conf.get("node.roles", [])

        if "data" in stored_roles:
            stored_roles.remove("data")

        self._opensearch.config.put(self.CONFIG_YML, "node.roles", stored_roles)

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

    def get_plugin(self, plugin_config: Dict[str, str] | List[str]) -> Dict[str, Any]:
        """Gets a list of configuration from opensearch.yml."""
        result = {}
        loaded_configs = self.load_node()
        key_list = plugin_config.keys() if isinstance(plugin_config, dict) else plugin_config
        for key in key_list:
            if key in loaded_configs:
                result[key] = loaded_configs[key]
        return result

    def add_plugin(self, plugin_config: Dict[str, str]) -> None:
        """Adds plugin configuration to opensearch.yml."""
        for key, val in plugin_config.items():
            self._opensearch.config.put(self.CONFIG_YML, key, val)

    def delete_plugin(self, plugin_config: List[str]) -> None:
        """Removes plugin configuration from opensearch.yml."""
        for key in plugin_config:
            self._opensearch.config.delete(self.CONFIG_YML, key)

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
