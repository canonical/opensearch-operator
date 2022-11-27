# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for Opensearch distributions."""

import json
import logging
import os
import pathlib
import socket
import subprocess
from abc import ABC, abstractmethod
from os.path import exists
from pathlib import Path
from typing import Dict, List, Optional, Set, Union

import requests
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.helper_networking import get_host_ip, is_reachable

# The unique Charmhub library identifier, never change it
LIBID = "7145c219467d43beb9c566ab4a72c454"

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

    def __init__(self, charm, peer_relation_name: str):
        self.paths = self._build_paths()
        self._create_directories()
        self._set_env_variables()

        self.config = YamlConfigSetter(base_path=self.paths.conf)
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

    def restart(self):
        """Restart the opensearch service."""
        if self.is_started():
            self.stop()

        self.start()

    def stop(self):
        """Exclude the allocation of this node."""
        try:
            self.add_allocation_exclusions(self._charm.unit_name)

            response = self.request("GET", "/_cluster/health?wait_for_status=green&timeout=60s")
            unassigned_shards = response.get("unassigned_shards", 0)
            if unassigned_shards > 0:
                self._charm.on_unassigned_shards(unassigned_shards)

            # stop the opensearch service
            self._stop_service()

            if self._charm.alternative_host:
                # remove the exclusion back
                self.remove_allocation_exclusions(
                    self._charm.unit_name, self._charm.alternative_host
                )
            else:
                # no node online, store in the app databag to exclude at a future start
                self._charm.append_allocation_exclusion(self._charm.unit_name)
        except Exception as e:
            logger.error(e)
            raise OpenSearchStopError()

    def add_allocation_exclusions(
        self, exclusions: Union[List[str], Set[str], str], host: str = None
    ):
        """Register new allocation exclusions."""
        exclusions = self.normalize_allocation_exclusions(exclusions)
        existing_exclusions = self._fetch_allocation_exclusions(host)
        self._store_allocation_exclusions(existing_exclusions.union(exclusions))

    def remove_allocation_exclusions(
        self, exclusions: Union[List[str], Set[str], str], host: str = None
    ):
        """This removes the allocation exclusions if needed."""
        exclusions = self.normalize_allocation_exclusions(exclusions)
        existing_exclusions = self._fetch_allocation_exclusions(host)
        self._store_allocation_exclusions(existing_exclusions - exclusions)

    def _store_allocation_exclusions(self, exclusions: Set[str], host: str = None):
        """Updates the cluster settings with the new allocation exclusions."""
        response = self.request(
            "PUT",
            "/_cluster/settings",
            {"transient": {"cluster.routing.allocation.exclude._name": ",".join(exclusions)}},
            host=host
        )
        if not response.get("acknowledged"):
            raise OpenSearchError()

    def _fetch_allocation_exclusions(self, host: str = None) -> Set[str]:
        """Fetch the registered allocation exclusions."""
        allocation_exclusions = set()
        try:
            resp = self.request("GET", "/_cluster/settings", host=host)
            exclusions = resp["transient"]["cluster"]["routing"]["allocation"]["exclude"]["_name"]
            allocation_exclusions = set(exclusions.split(","))
        except KeyError:
            # no allocation exclusion set
            pass
        finally:
            return allocation_exclusions

    @abstractmethod
    def _stop_service(self):
        """Stop the opensearch service."""
        pass

    def is_started(self) -> bool:
        """Check if OpenSearch is started."""
        reachable = is_reachable(self.host, self.port)
        if not reachable:
            logger.error("Cannot connect to the OpenSearch server...")

        return reachable

    def is_node_up(self) -> bool:
        """Get status of current node. This assumes OpenSearch is Running."""
        if not self.is_started():
            return False

        try:
            self.request("GET", "/_nodes")
            return True
        except (OpenSearchHttpError, Exception) as e:
            logger.exception(e)
            return False

    @property
    def node_id(self) -> str:
        """Get the OpenSearch node id corresponding to the current unit."""
        nodes = self.request("GET", "/_nodes").get("nodes")

        for node_id, node in nodes.items():
            if node["name"] == self._charm.unit_name:
                return node_id

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
    ) -> Union[Dict[str, any], List[any]]:
        """Make an HTTP request.

        Args:
            method: matching the known http methods.
            endpoint: relative to the base uri.
            payload: JSON / map body payload.
            host: host of the node we wish to make a request on, by default current host.
        """
        if None in [endpoint, method]:
            raise ValueError("endpoint or method missing")

        if endpoint.startswith("/"):
            endpoint = endpoint[1:]

        target_host = host if host else self.host
        if not is_reachable(target_host, self.port):
            logger.error(f"Host {target_host}:{self.port} not reachable.")
            raise OpenSearchHttpError()

        full_url = f"https://{target_host}:{self.port}/{endpoint}"
        try:
            with requests.Session() as s:
                s.auth = ("admin", self._charm.secrets.get(Scope.APP, "admin_password"))

                resp = s.request(
                    method=method.upper(),
                    url=full_url,
                    data=json.dumps(payload),
                    verify=f"{self.paths.certs}/chain.pem",
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                )

                resp.raise_for_status()
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

        try:
            output = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True,
                encoding="utf-8",
                timeout=15,
                env=os.environ,
            )

            logger.debug(f"{command}:\n{output.stdout}")

            if output.returncode != 0:
                logger.error(f"{command}:\n Stderr: {output.stderr}\n Stdout: {output.stdout}")
                raise OpenSearchCmdError()
        except (TimeoutError, subprocess.TimeoutExpired):
            raise OpenSearchCmdError()

    @abstractmethod
    def _build_paths(self) -> Paths:
        """Build the Paths object."""
        pass

    def _create_directories(self) -> None:
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

    @property
    def network_hosts(self) -> List[str]:
        """All HTTP/Transport hosts for the current node."""
        return [socket.getfqdn(), self.host]

    @property
    def port(self) -> int:
        """Return Port of OpenSearch."""
        return 9200

    @staticmethod
    def normalize_allocation_exclusions(exclusions: Union[List[str], Set[str], str]) -> Set[str]:
        """Normalize a list of allocation exclusions into a set."""
        if type(exclusions) is list:
            exclusions = set(exclusions)
        elif type(exclusions) is str:
            exclusions = set(exclusions.split(","))

        return exclusions

    @staticmethod
    def missing_sys_requirements() -> List[str]:
        """Checks the system requirements."""
        missing_requirements = []

        max_map_count = int(subprocess.getoutput("sysctl vm.max_map_count").split("=")[-1].strip())
        if max_map_count < 262144:
            missing_requirements.append("vm.max_map_count should be at least 262144")

        swappiness = int(subprocess.getoutput("sysctl vm.swappiness").split("=")[-1].strip())
        if swappiness > 0:
            missing_requirements.append("vm.swappiness should be 0")

        tcp_retries = int(
            subprocess.getoutput("sysctl net.ipv4.tcp_retries2").split("=")[-1].strip()
        )
        if tcp_retries > 5:
            missing_requirements.append("net.ipv4.tcp_retries2 should be 5")

        return missing_requirements
