# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for Opensearch distributions."""

import logging
import os
import pathlib
import subprocess
from abc import ABC, abstractmethod
from os.path import exists
from pathlib import Path
from typing import Dict, List, Optional

import requests
from charms.opensearch.v0.helpers.conf_setter import ConfigSetter
from charms.opensearch.v0.helpers.networking import get_host_ip
from charms.opensearch.v0.tls_constants import CertType

# The unique Charmhub library identifier, never change it
LIBID = "f4bd9c1dad554f9ea52954b8181cdc19"
LIBAPI = 0
LIBPATCH = 0


logger = logging.getLogger(__name__)


class OpenSearchError(Exception):
    """Base exception class for OpenSearch errors."""


class OpenSearchMissingError(OpenSearchError):
    """Exception thrown when an action is attempted on OpenSearch when it's not installed."""


class OpenSearchInstallError(OpenSearchError):
    """Exception thrown when OpenSearch fails to be installed."""


class OpenSearchMissingSysReqError(OpenSearchError):
    """Exception thrown when OpenSearch fails to be installed."""

    def __init__(self, missing_requirements: List[str]):
        self.missing_requirements = missing_requirements


class OpenSearchStartError(OpenSearchError):
    """Exception thrown when OpenSearch fails to start."""


class OpenSearchStopError(OpenSearchError):
    """Exception thrown when OpenSearch fails to stop."""


class OpenSearchRestartError(OpenSearchError):
    """Exception thrown when OpenSearch fails to restart."""


class OpenSearchNotStartedError(OpenSearchError):
    """Exception thrown when attempting an operation when the OpenSearch service is stopped."""


class OpenSearchCmdError(OpenSearchError):
    """Exception thrown when an OpenSearch bin command fails."""


class OpenSearchHttpError(OpenSearchError):
    """Exception thrown when an OpenSearch REST call fails."""


class Paths:
    """This class represents the group of Paths that need to be exposed."""

    def __init__(self, home: str, conf: str, data: str, logs: str, jdk: str, tmp: str):
        """Constructor of Paths.

        Args:
            home: Home path of Opensearch, equivalent to the env variable ${OPENSEARCH_HOME}
            conf: Path to the config folder of opensearch
            data: Path to the data folder of opensearch
            logs: Path to the logs folder of opensearch
            jdk: Path of the jdk that comes bundled with the opensearch distro
            tmp: JNA temporary directory
        """
        self.home = home
        self.conf = conf
        self.plugins = f"{home}/plugins"
        self.data = data
        self.logs = logs
        self.jdk = jdk
        self.tmp = tmp
        self.certs = f"{conf}/certificates"  # must be under config
        self.certs_relative = "certificates"


class OpenSearchDistribution(ABC):
    """This class represents an interface for a Distributed Opensearch (snap, tarball, oci img)."""

    SERVICE_NAME = "daemon"

    def __init__(self, charm, peer_relation_name):
        self.paths = self._build_paths()
        self.__create_directories()
        self._set_env_variables()

        self.config = ConfigSetter(base_path=self.paths.conf)
        self._charm = charm
        self._peer_relation_name = peer_relation_name

    @abstractmethod
    def install(self):
        """Install the package."""
        pass

    @abstractmethod
    def start(self):
        """Start the opensearch service."""
        pass

    @abstractmethod
    def restart(self):
        """Restart the opensearch service."""
        pass

    @abstractmethod
    def stop(self):
        """Stop the opensearch service."""
        pass

    def is_node_up(self) -> bool:
        """Get status of current node."""
        try:
            self.request("GET", "/_nodes")
            return True
        except (OpenSearchHttpError, Exception) as e:
            logger.error(e)
            return False

    def run_bin(self, bin_script_name: str, args: str = None):
        """Run opensearch provided bin command, relative to OPENSEARCH_HOME/bin."""
        script_path = f"{self.paths.home}/bin/{bin_script_name}"
        self._run_cmd(f"chmod a+x {script_path}")

        self._run_cmd(script_path, args)

    def run_script(self, script_name: str, args: str = None):
        """Run script provided by Opensearch in another directory, relative to OPENSEARCH_HOME."""
        script_path = f"{self.paths.home}/{script_name}"
        self._run_cmd(f"chmod a+x {script_path}")

        self._run_cmd(f"{script_path}", args)

    def request(
        self,
        method: str,
        endpoint: str,
        payload: Optional[Dict[str, any]] = None,
        host: Optional[str] = None,
    ) -> Dict[str, any]:
        """Make an HTTP request.

        Args:
            method: matching the known http methods.
            endpoint: relative to the base uri.
            payload: JSON / map body payload.
            host: host of the node we wish to make a request on, by default current host.
        """
        if None in [endpoint, method]:
            raise ValueError("endpoint or method missing")

        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"

        full_url = f"https://{self.host if host is None else host}:9200{endpoint}"
        try:
            with requests.Session() as s:
                resp = s.request(
                    method=method.upper(),
                    url=full_url,
                    data=payload,
                    verify=True,
                    cert=f"{self.paths.certs}/{CertType.UNIT_HTTP}.cert",
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                )
        except requests.exceptions.RequestException as e:
            logger.error(f"Request {method} to {full_url} with payload: {payload} failed. \n{e}")
            raise OpenSearchHttpError()

        return resp.json()

    @staticmethod
    def write_file(path: str, data: str, override: bool = True):
        """Persists data into file. Useful for files generated on the fly, such as certs etc."""
        if not override and exists(path):
            return

        parent_dir_path = "/".join(path.split("/")[:-1])
        if parent_dir_path:
            pathlib.Path(parent_dir_path).mkdir(parents=True, exist_ok=True)

        with open(path, mode="w") as f:
            f.write(data)

    @staticmethod
    def _run_cmd(command: str, args: str = None):
        """Run command.

        Arg:
            command: can contain arguments
            args: command line arguments
        """
        if args is not None:
            command = f"{command} {args}"

        logger.debug(f"Executing command: {command}")

        output = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
            encoding="utf-8",
            env=os.environ,
        )

        if output.returncode != 0:
            logger.error(f"{command}:\n Stderr: {output.stderr}\n Stdout: {output.stdout}")
            raise OpenSearchCmdError()

        logger.debug(f"{command}:\n{output.stdout}")

    @abstractmethod
    def _build_paths(self) -> Paths:
        """Build the Paths object."""
        pass

    def __create_directories(self) -> None:
        """Create the directories defined in self.paths."""
        for dir_path in self.paths.__dict__.values():
            Path(dir_path).mkdir(parents=True, exist_ok=True)

    def _set_env_variables(self):
        """Set the necessary environment variables."""
        os.environ["OPENSEARCH_HOME"] = self.paths.home
        os.environ["OPENSEARCH_JAVA_HOME"] = self.paths.jdk
        os.environ["OPENSEARCH_PATH_CONF"] = self.paths.conf
        os.environ["OPENSEARCH_TMPDIR"] = self.paths.tmp
        os.environ["OPENSEARCH_PLUGINS"] = self.paths.plugins

    @property
    def host(self) -> str:
        """Host IP address of the current node."""
        return get_host_ip(self._charm, self._peer_relation_name)

    @staticmethod
    def check_missing_sys_requirements() -> None:
        """Checks the system requirements."""
        missing_requirements = []

        file_descriptors = int(subprocess.getoutput("ulimit -n"))
        logger.debug(f"file_descriptors: {file_descriptors}")
        if file_descriptors < 65535:
            missing_requirements.append("ulimit -n should be at least 65535")

        max_map_count = int(subprocess.getoutput("sysctl vm.max_map_count").split("=")[-1].strip())
        logger.debug(f"max_map_count: {max_map_count}")
        if max_map_count < 262144:
            missing_requirements.append("vm.max_map_count should be at least 262144")

        swappiness = int(subprocess.getoutput("sysctl vm.swappiness").split("=")[-1].strip())
        logger.debug(f"swappiness: {swappiness}")
        if swappiness > 60:  # != 0: TODO
            missing_requirements.append("vm.swappiness should be 0")

        tcp_retries = int(
            subprocess.getoutput("sysctl net.ipv4.tcp_retries2").split("=")[-1].strip()
        )
        logger.debug(f"tcp_retries: {tcp_retries}")
        if tcp_retries > 15:  # > 5: TODO
            missing_requirements.append("net.ipv4.tcp_retries2 should be 5")

        if len(missing_requirements) > 0:
            raise OpenSearchMissingSysReqError(missing_requirements)
