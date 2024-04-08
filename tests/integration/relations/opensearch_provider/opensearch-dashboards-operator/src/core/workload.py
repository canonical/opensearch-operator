#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base objects for workload operations across VM + K8s charms."""
from abc import ABC, abstractmethod

from literals import PATHS


class ODPaths:
    """Collection of expected paths for the Opensearch Dashboards workload."""

    def __init__(self):
        self.conf_path = PATHS["CONF"]
        self.data_path = PATHS["DATA"]
        self.binaries_path = PATHS["BIN"]
        self.logs_path = PATHS["LOGS"]

    @property
    def data_dir(self) -> str:
        """The directory where Opensearch Dashboards will store the in-memory database snapshots."""
        return f"{self.data_path}/data"

    @property
    def properties(self) -> str:
        """The main properties filepath.

        Contains all the main configuration for the service.
        """
        return f"{self.conf_path}/opensearch_dashboards.yml"

    @property
    def server_key(self) -> str:
        """The private-key for the service to identify itself with for TLS auth."""
        return f"{self.conf_path}/certificates/server.key"

    @property
    def ca(self) -> str:
        """The shared cluster CA."""
        return f"{self.conf_path}/certificates/ca.pem"

    @property
    def certificate(self) -> str:
        """The certificate for the service to identify itself with for TLS auth."""
        return f"{self.conf_path}/certificates/server.pem"

    @property
    def opensearch_ca(self) -> str:
        """The certificate for the service to identify itself with for TLS auth."""
        return f"{self.conf_path}/certificates/opensearch_ca.pem"


class WorkloadBase(ABC):
    """Base interface for common workload operations."""

    paths = ODPaths()

    @abstractmethod
    def start(self) -> None:
        """Starts the workload service."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stops the workload service."""
        ...

    @abstractmethod
    def restart(self) -> None:
        """Restarts the workload service."""
        ...

    @abstractmethod
    def read(self, path: str) -> list[str]:
        """Reads a file from the workload.

        Args:
            path: the full filepath to read from

        Returns:
            List of string lines from the specified path
        """
        ...

    @abstractmethod
    def write(self, content: str, path: str) -> None:
        """Writes content to a workload file.

        Args:
            content: string of content to write
            path: the full filepath to write to
        """
        ...

    @abstractmethod
    def exec(self, command: list[str], working_dir: str | None = None) -> None:
        """Runs a command on the workload substrate."""
        ...

    @property
    @abstractmethod
    def alive(self) -> bool:
        """Checks that the workload is alive."""
        ...

    @property
    @abstractmethod
    def healthy(self) -> bool:
        """Checks that the workload is healthy."""
        ...
