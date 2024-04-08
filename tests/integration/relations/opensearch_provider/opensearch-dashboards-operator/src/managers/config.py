#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for for handling configuration building + writing."""
import logging
from typing import TYPE_CHECKING

from ops.model import ConfigData

if TYPE_CHECKING:
    pass

from core.cluster import SUBSTRATES, ClusterState
from core.workload import WorkloadBase

logger = logging.getLogger(__name__)


DEFAULT_PROPERTIES = """
opensearch.ssl.verificationMode: full
opensearch.requestHeadersWhitelist: [authorization, securitytenant]
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: [Private, Global]
opensearch_security.readonly_mode.roles: [kibana_read_only]
opensearch_security.cookie.secure: true
"""

TLS_PROPERTIES = """
server.ssl.enabled: true
"""

LOG_PROPERTIES = """
logging.verbose: true
"""


class ConfigManager:
    """Manager for for handling configuration building + writing."""

    def __init__(
        self,
        state: ClusterState,
        workload: WorkloadBase,
        substrate: SUBSTRATES,
        config: ConfigData,
    ):
        self.state = state
        self.workload = workload
        self.substrate = substrate
        self.config = config

    @property
    def log_level(self) -> str:
        """Return the Opensearch-compilant logging level set by the user.

        Returns:
            String with these possible values: DEBUG, INFO, WARN, ERROR
        """
        # FIXME: use pydantic config models for this validation instead
        permitted_levels = ["INFO", "WARNING", "ERROR"]
        config_log_level = self.config["log-level"]

        if config_log_level not in permitted_levels:
            logger.error(
                f"Invalid log-level config value of {config_log_level}. "
                f"Must be one of {','.join(permitted_levels)}. Defaulting to 'INFO'"
            )
            config_log_level = "INFO"

        # Remapping to WARN that is generally used in Java applications based on log4j and logback.
        if config_log_level == "WARNING":
            return "logging.quiet"
        elif config_log_level == "INFO":
            return "logging.verbose"
        elif config_log_level == "ERROR":
            return "logging.silent"

        return ""

    @property
    def dashboard_properties(self) -> list[str]:
        """Build the zoo.cfg content.

        Returns:
            List of properties to be set to zoo.cfg config file
        """
        properties = DEFAULT_PROPERTIES.split("\n")

        opensearch_user = (
            self.state.opensearch_server.username if self.state.opensearch_server else ""
        )
        opensearch_password = (
            self.state.opensearch_server.password if self.state.opensearch_server else ""
        )

        opensearch_endpoints = (
            ", ".join(f"https://{endpoint}" for endpoint in self.state.opensearch_server.endpoints)
            if self.state.opensearch_server and len(self.state.opensearch_server.endpoints) > 0
            else ""
        )

        opensearch_ca = self.workload.paths.opensearch_ca if self.state.opensearch_server else ""

        properties += [f"server.host: '{self.state.unit_server.private_ip}'"]
        properties += (
            [
                f"opensearch.username: {opensearch_user}",
                f"opensearch.password: {opensearch_password}",
            ]
            if opensearch_user and opensearch_password
            else []
        )

        properties += (
            [f"opensearch.hosts: [{opensearch_endpoints}]"] if opensearch_endpoints else []
        )

        if opensearch_ca:
            properties += [f'opensearch.ssl.certificateAuthorities: [ "{opensearch_ca}" ]']

        if self.state.cluster.tls:
            properties += TLS_PROPERTIES.split("\n") + [
                f"server.ssl.certificate: {self.workload.paths.certificate}",
                f"server.ssl.key: {self.workload.paths.server_key}",
            ]

        # Log-level
        properties += [f"{self.log_level}: true"]

        # Paths
        properties += [f"path.data: {self.workload.paths.data_path}"]

        return properties

    @property
    def current_properties(self) -> list[str]:
        """The current configuration properties set to zoo.cfg."""
        return self.workload.read(self.workload.paths.properties)

    @property
    def current_env(self) -> list[str]:
        """The current /etc/environment variables."""
        return self.workload.read(path="/etc/environment")

    @property
    def static_properties(self) -> list[str]:
        """Build the zoo.cfg content, without dynamic options.

        Returns:
            List of static properties to compared to current zoo.cfg
        """
        return self.build_static_properties(self.dashboard_properties)

    def set_dashboard_properties(self) -> None:
        """Writes built config file."""
        self.workload.write(
            content="\n".join(self.dashboard_properties),
            path=self.workload.paths.properties,
        )

    @staticmethod
    def build_static_properties(properties: list[str]) -> list[str]:
        """Removes dynamic config options from list of properties.

        Args:
            properties: the properties to make static

        Returns:
            List of static properties
        """
        return [
            prop
            for prop in properties
            if ("clientPort" not in prop and "secureClientPort" not in prop)
        ]

    def config_changed(self) -> bool:
        """Compares expected vs actual config that would require a restart to apply."""
        server_properties = self.build_static_properties(self.current_properties)
        config_properties = self.static_properties

        properties_changed = set(server_properties) ^ set(config_properties)

        if not properties_changed:
            return False

        if properties_changed:
            logger.info(
                (
                    f"Server.{self.state.unit_server.unit_id} updating properties - "
                    f"OLD PROPERTIES = {set(server_properties) - set(config_properties)}, "
                    f"NEW PROPERTIES = {set(config_properties) - set(server_properties)}"
                )
            )
            self.set_dashboard_properties()

        return True
