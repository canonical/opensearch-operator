# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for Opensearch distributions."""
import json
import logging
import os
import pathlib
import socket
import subprocess
import time
from abc import ABC, abstractmethod
from datetime import datetime
from functools import cached_property
from os.path import exists
from typing import Dict, List, Optional, Set, Union

import requests
import urllib3.exceptions
from charms.opensearch.v0.constants_secrets import ADMIN_PW
from charms.opensearch.v0.helper_cluster import Node
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.helper_networking import (
    get_host_ip,
    is_reachable,
    reachable_hosts,
)
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchError,
    OpenSearchHttpError,
    OpenSearchKeystoreError,
    OpenSearchPluginError,
    OpenSearchStartTimeoutError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_plugins import OpenSearchPluginManager

# The unique Charmhub library identifier, never change it
LIBID = "7145c219467d43beb9c566ab4a72c454"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2


logger = logging.getLogger(__name__)


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
        self.seed_hosts = f"{conf}/unicast_hosts.txt"


class OpenSearchDistribution(ABC):
    """This class represents an interface for a Distributed Opensearch (snap, tarball, oci img)."""

    SERVICE_NAME = "daemon"

    def __init__(self, charm, peer_relation_name: str):
        self.paths = self._build_paths()
        self._set_env_variables()

        self.config = YamlConfigSetter(base_path=self.paths.conf)
        self._charm = charm
        self._peer_relation_name = peer_relation_name
        self._plugin_manager = OpenSearchPluginManager(self._charm)

    def install(self):
        """Install the package."""
        pass

    def start(self, wait_until_http_200: bool = True):
        """Start the opensearch service."""

        def _is_connected():
            return self.is_node_up() if wait_until_http_200 else self.is_started()

        if self.is_started():
            return

        # start the opensearch service
        self._start_service()

        start = datetime.now()
        while not _is_connected() and (datetime.now() - start).seconds < 75:
            time.sleep(3)
        else:
            raise OpenSearchStartTimeoutError()

    def restart(self):
        """Restart the opensearch service."""
        if self.is_started():
            self.stop()

        self.start()

    def stop(self):
        """Stop OpenSearch."""
        # stop the opensearch service
        self._stop_service()

        start = datetime.now()
        while self.is_started() and (datetime.now() - start).seconds < 60:
            time.sleep(3)

    @abstractmethod
    def _start_service(self):
        """Start the opensearch service."""
        pass

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

    @abstractmethod
    def is_failed(self) -> bool:
        """Check if OpenSearch daemon has failed."""
        pass

    def is_node_up(self) -> bool:
        """Get status of current node. This assumes OpenSearch is Running."""
        if not self.is_started():
            return False

        try:
            resp_code = self.request("GET", "/_nodes", resp_status_code=True)
            return resp_code < 400
        except (OpenSearchHttpError, Exception):
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

    def request(  # noqa
        self,
        method: str,
        endpoint: str,
        payload: Optional[Union[str, Dict[str, any], List[Dict[str, any]]]] = None,
        host: Optional[str] = None,
        alt_hosts: Optional[List[str]] = None,
        check_hosts_reach: bool = True,
        resp_status_code: bool = False,
        retries: int = 0,
        timeout: int = 5,
    ) -> Union[Dict[str, any], List[any], int]:
        """Make an HTTP request.

        Args:
            method: matching the known http methods.
            endpoint: relative to the base uri.
            payload: str, JSON obj or array body payload.
            host: host of the node we wish to make a request on, by default current host.
            alt_hosts: in case the default host is unreachable, fallback/alternative hosts.
            check_hosts_reach: if true, performs a ping for each host
            resp_status_code: whether to only return the HTTP code from the response.
            retries: number of retries
            timeout: number of seconds before a timeout happens

        Raises:
            ValueError if method or endpoint are missing
            OpenSearchHttpError if hosts are unreachable
            requests.HTTPError if connection to opensearch fails
        """

        def full_urls() -> List[str]:
            """Returns a list of reachable hosts."""
            primary_host = host or self.host
            target_hosts = [primary_host]
            if alt_hosts:
                target_hosts.extend(
                    [alt_host for alt_host in alt_hosts if alt_host != primary_host]
                )

            if not check_hosts_reach:
                return target_hosts

            return [
                f"https://{host_candidate}:{self.port}/{endpoint}"
                for host_candidate in reachable_hosts(target_hosts)
            ]

        def call(
            remaining_retries: int,
            return_failed_resp: bool,
            error_response: Optional[requests.Response] = None,
        ) -> requests.Response:
            """Performs an HTTP request."""
            if remaining_retries < 0:
                if error_response is None:
                    raise OpenSearchHttpError()

                if return_failed_resp:
                    return error_response

                raise OpenSearchHttpError(
                    response_body=error_response.text, response_code=error_response.status_code
                )

            urls = full_urls()
            if not urls:
                logger.error(
                    f"Host {host or self.host}:{self.port} and alternative_hosts: {alt_hosts or []} not reachable."
                )
                raise OpenSearchHttpError()

            try:
                with requests.Session() as s:
                    s.auth = (
                        "admin",
                        self._charm.secrets.get(Scope.APP, ADMIN_PW),
                    )

                    request_kwargs = {
                        "method": method.upper(),
                        "url": urls[0],
                        "verify": f"{self.paths.certs}/chain.pem",
                        "headers": {
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                        },
                        "timeout": (timeout, timeout),
                    }
                    if payload:
                        request_kwargs["data"] = (
                            json.dumps(payload) if not isinstance(payload, str) else payload
                        )

                    response = s.request(**request_kwargs)

                    return response
            except (requests.exceptions.RequestException, urllib3.exceptions.HTTPError) as e:
                logger.error(
                    f"Request {method} to {urls[0]} with payload: {payload} failed. "
                    f"(Attempts left: {remaining_retries})\n{e}"
                )
                time.sleep(1)
                return call(
                    remaining_retries - 1,
                    return_failed_resp,
                    e.response if isinstance(e, requests.exceptions.HTTPError) else None,
                )

        if None in [endpoint, method]:
            raise ValueError("endpoint or method missing")

        if endpoint.startswith("/"):
            endpoint = endpoint[1:]

        resp = call(retries, resp_status_code)

        if resp_status_code:
            return resp.status_code

        try:
            return resp.json()
        except requests.JSONDecodeError:
            raise OpenSearchHttpError(response_body=resp.text)

    def write_file(self, path: str, data: str, override: bool = True):
        """Persists data into file. Useful for files generated on the fly, such as certs etc."""
        if not override and exists(path):
            return

        parent_dir_path = "/".join(path.split("/")[:-1])
        if parent_dir_path:
            pathlib.Path(parent_dir_path).mkdir(parents=True, exist_ok=True)

        with open(path, mode="w") as f:
            f.write(data)

    def add_plugin_without_restart(self, plugin: str, batch: bool = False) -> bool:
        """Add a plugin to this node. Restart must be managed in separated."""
        try:
            args = "install"
            if batch:
                args += " --batch"
            args += f" {plugin}"
            self._run_cmd(f"{self.paths.home}/bin/opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "already exists" in e.stderr:
                return
            raise OpenSearchPluginError(f"Failed to install plugin {plugin}")

    def remove_plugin_without_restart(self, plugin):
        """Remove a plugin without restarting the node."""
        try:
            args = f"remove {plugin}"
            self._run_cmd(f"{self.paths.home}/bin/opensearch-plugin", args)
        except OpenSearchCmdError as e:
            if "not found" in e.stderr:
                logger.info("Plugin {plugin} not found, leaving remove method")
                return
            raise OpenSearchPluginError(f"Failed to remove plugin {plugin}")

    def list_plugins(self):
        """List plugins."""
        try:
            self._run_cmd(f"{self.paths.home}/bin/opensearch-plugin", "list")
        except OpenSearchCmdError:
            raise OpenSearchPluginError("Failed to list plugins")

    def add_to_keystore(self, key: str, value: str, force: bool = False):
        """Adds a given key to the "opensearch" keystore."""
        if not value:
            raise OpenSearchKeystoreError("Missing keystore value")
        args = "add " if not force else "add --force "
        args += f"{key}"
        try:
            # Add newline to the end of the key, if missing
            v = value + ("" if value[-1] == "\n" else "\n")
            self._run_cmd(f"{self.paths.home}/bin/opensearch-keystore", args, input=v)
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(e)

    def remove_from_keystore(self, key: str):
        """Removes a given key from "opensearch" keystore."""
        args = f"remove {key}"
        try:
            self._run_cmd(f"{self.paths.home}/bin/opensearch-keystore", args)
        except OpenSearchCmdError as e:
            if "does not exist in the keystore" in e.stderr:
                return
            raise OpenSearchKeystoreError(e)

    @staticmethod
    def _run_cmd(command: str, args: str = None, input: str = None) -> str:
        """Run command.

        Arg:
            command: can contain arguments
            args: command line arguments
            input: enter string to the process

        Returns the stdout
        """
        if args is not None:
            command = f"{command} {args}"

        logger.debug(f"Executing command: {command}")

        try:
            output = subprocess.run(
                command,
                input=input,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True,
                encoding="utf-8",
                timeout=25,
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

    def _set_env_variables(self):
        """Set the necessary environment variables."""
        os.environ["OPENSEARCH_HOME"] = self.paths.home
        os.environ["OPENSEARCH_JAVA_HOME"] = self.paths.jdk
        os.environ["OPENSEARCH_PATH_CONF"] = self.paths.conf
        os.environ["OPENSEARCH_TMPDIR"] = self.paths.tmp
        os.environ["OPENSEARCH_PLUGINS"] = self.paths.plugins

    @cached_property
    def node_id(self) -> str:
        """Get the OpenSearch node id corresponding to the current unit."""
        nodes = self.request("GET", "/_nodes").get("nodes")

        for n_id, node in nodes.items():
            if node["name"] == self._charm.unit_name:
                return n_id

    @property
    def roles(self) -> List[str]:
        """Get the list of the roles assigned to this node."""
        try:
            nodes = self.request("GET", f"/_nodes/{self.node_id}", alt_hosts=self._charm.alt_hosts)
            return nodes["nodes"][self.node_id]["roles"]
        except OpenSearchHttpError:
            return self.config.load("opensearch.yml")["node.roles"]

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

    def current(self) -> Node:
        """Returns current Node."""
        return Node(self._charm.unit_name, self.roles, self.host)

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

    @property
    def version(self) -> str:
        """Returns the version number of this opensearch instance.

        Raises:
            OpenSearchError if the GET request fails.
        """
        try:
            return self.request("GET", "/").get("version").get("number")
        except OpenSearchHttpError:
            logger.error(
                "failed to get root endpoint, implying that this node is offline. Retry once node is online."
            )
            raise OpenSearchError()
