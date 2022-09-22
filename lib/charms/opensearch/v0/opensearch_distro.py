# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import subprocess
from typing import Dict, Optional
import requests

from charms.opensearch.v0.helpers.conf_setter import ConfigSetter
from charms.opensearch.v0.helpers.networking import get_host_ip
from charms.opensearch.v0.opensearch_tls import CertType

# The unique Charmhub library identifier, never change it
LIBID = "f4bd9c1dad554f9ea52954b8181cdc19"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class OpenSearchError(Exception):
    """Base exception class for OpenSearch errors"""


class OpenSearchMissingError(OpenSearchError):
    """Exception thrown when an action is attempted on OpenSearch when it's not installed"""


class OpenSearchInstallError(OpenSearchError):
    """Exception thrown when OpenSearch fails to be installed"""


class OpenSearchStartError(OpenSearchError):
    """Exception thrown when OpenSearch fails to start"""


class OpenSearchStopError(OpenSearchError):
    """Exception thrown when OpenSearch fails to stop"""


class OpenSearchRestartError(OpenSearchError):
    """Exception thrown when OpenSearch fails to restart"""


class OpenSearchNotStartedError(OpenSearchError):
    """Exception thrown when attempting an operation when the OpenSearch service is stopped"""


class OpenSearchCmdError(OpenSearchError):
    """Exception thrown when an OpenSearch bin command fails"""


class OpenSearchHttpError(OpenSearchError):
    """Exception thrown when an OpenSearch REST call fails"""


class OpenSearchDistribution:
    """This class represents an interface for a Distributed Opensearch, be it a Snap or OCI image etc."""

    SERVICE_NAME = "daemon"

    def __init__(self, charm, peer_relation_name):
        self.config = ConfigSetter(base_path=self.path_conf)
        self._charm = charm
        self._peer_relation_name = peer_relation_name

    def install(self):
        """Install the package"""
        pass

    def start(self):
        """Start the opensearch service"""
        pass

    def restart(self):
        """Restart the opensearch service"""
        pass

    def stop(self):
        """Stop the opensearch service"""
        pass

    def run_bin(self, bin_script_name: str, args: str = None):
        """Run command using an opensearch bin provided script, relative to OPENSEARCH_HOME/bin"""
        self._run_cmd(f"{self.path_home}/bin/{bin_script_name}", args)

    def run_script(self, script_name: str, args: str = None):
        """Run script that is provided by Opensearch in another directory, relative to OPENSEARCH_HOME"""
        self._run_cmd(f"{self.path_home}/{script_name}", args)

    def request(self, method: str, endpoint: str, payload: Optional[Dict[str, any]] = None) -> Dict[str, any]:
        """Make an HTTP request, endpoint must be relative to the base uri and verb matching the http methods"""
        if None in [endpoint, method]:
            raise ValueError("endpoint or method missing")

        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"

        full_url = f"https://{self.host}{endpoint}"
        try:
            with requests.Session() as s:
                resp = s.request(
                    method=method.upper(),
                    url=full_url,
                    data=payload,
                    verify=True,
                    cert=f"{self.path_certs}/{CertType.UNIT_HTTP}.cert",
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json"
                    })
        except requests.exceptions.RequestException as e:
            logger.error(f"Request {method} to {full_url} with payload: {payload} failed. \n{e}")
            raise OpenSearchHttpError()

        return resp.json()

    @staticmethod
    def write_file(path: str, data: str):
        """Persists data into file. Useful for files generated on the fly, such as certs and keys etc."""
        with open(path, mode="w") as f:
            f.write(data)

    @staticmethod
    def _run_cmd(command: str, args: str = None, cmd_has_args: bool = False):
        """Run command.
        command -> can contain args, in which case the cmd_has_args must be set to true
        """
        cmd = command.split() if cmd_has_args else [command]
        if args:
            cmd.extend(args.split())

        try:
            output = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, check=True, encoding='utf-8')
            logger.debug(f"{' '.join(cmd)}: \n{output}")
        except subprocess.CalledProcessError as e:
            logger.error(f"{' '.join(cmd)}: \n{e}")
            raise OpenSearchCmdError()

    @property
    def path_home(self) -> str:
        """Home path of Opensearch, equivalent to the env variable ${OPENSEARCH_HOME}"""
        return ""

    @property
    def path_conf(self) -> str:
        """Path to the config folder of opensearch"""
        return ""

    @property
    def path_plugins(self) -> str:
        """Path to the plugins directory of opensearch"""
        return f"{self.path_home}/plugins"

    @property
    def path_certs(self) -> str:
        """Path to the directory where certificates are stored, must be under config"""
        return f"{self.path_conf}/certificates"

    @property
    def host(self) -> str:
        """Host IP address of the current node."""
        return get_host_ip(self._charm, self._peer_relation_name)
