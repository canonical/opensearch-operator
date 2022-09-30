# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for Opensearch distributions."""

import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, Optional

import requests
from charms.opensearch.v0.helpers.conf_setter import ConfigSetter
from charms.opensearch.v0.helpers.networking import get_host_ip
from charms.opensearch.v0.tls_constants import CertType

# The unique Charmhub library identifier, never change it
LIBID = "f4bd9c1dad554f9ea52954b8181cdc19"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class OpenSearchError(Exception):
    """Base exception class for OpenSearch errors."""


class OpenSearchMissingError(OpenSearchError):
    """Exception thrown when an action is attempted on OpenSearch when it's not installed."""


class OpenSearchInstallError(OpenSearchError):
    """Exception thrown when OpenSearch fails to be installed."""


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


class OpenSearchDistribution(ABC):
    """This class represents an interface for a Distributed Opensearch (snap, tarball, oci img)."""

    SERVICE_NAME = "daemon"

    def __init__(self, charm, peer_relation_name):
        self.paths = self._build_paths()
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

    def run_bin(self, bin_script_name: str, args: str = None):
        """Run opensearch provided bin command, relative to OPENSEARCH_HOME/bin."""
        self._run_cmd(f"{self.paths.home}/bin/{bin_script_name}", args)

    def run_script(self, script_name: str, args: str = None):
        """Run script provided by Opensearch in another directory, relative to OPENSEARCH_HOME."""
        self._run_cmd(f"{self.paths.home}/{script_name}", args)

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

        full_url = f"https://{self.host if host is None else host}{endpoint}"
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
    def write_file(path: str, data: str):
        """Persists data into file. Useful for files generated on the fly, such as certs etc."""
        with open(path, mode="w") as f:
            f.write(data)

    @staticmethod
    def _run_cmd(command: str, args: str = None, cmd_has_args: bool = False):
        """Run command.

        Arg:
            command: can contain args, in which case the cmd_has_args must be set to true
            args: command line arguments
            cmd_has_args: if the command argument contains the command + args
        """
        cmd = command.split() if cmd_has_args else [command]
        if args is not None:
            cmd.extend(args.split())

        try:
            output = subprocess.run(
                cmd, stdout=subprocess.PIPE, text=True, check=True, encoding="utf-8"
            )
            logger.debug(f"{' '.join(cmd)}: \n{output}")
        except subprocess.CalledProcessError as e:
            logger.error(f"{' '.join(cmd)}: \n{e}")
            raise OpenSearchCmdError()

    @abstractmethod
    def _build_paths(self) -> Paths:
        """Build the Paths object."""
        pass

    @property
    def host(self) -> str:
        """Host IP address of the current node."""
        return get_host_ip(self._charm, self._peer_relation_name)
