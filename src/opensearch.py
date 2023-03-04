# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class we manage opensearch distributions specific to the VM charm.

This class handles install / start / stop of opensearch services.
It also exposes some properties and methods for interacting with an OpenSearch Installation
"""
import logging
import os
import time
from datetime import datetime

import requests
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution, Paths
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchInstallError,
    OpenSearchMissingError,
    OpenSearchStartError,
    OpenSearchStopError,
)
from charms.operator_libs_linux.v1 import snap
from charms.operator_libs_linux.v1.snap import SnapError
from charms.operator_libs_linux.v1.systemd import _systemctl
from overrides import override
from tenacity import retry, stop_after_attempt, wait_exponential

from utils import extract_tarball

logger = logging.getLogger(__name__)


class OpenSearchSnap(OpenSearchDistribution):
    """Snap distribution of opensearch, only overrides properties and logic proper to the snap."""

    _BASE_SNAP_DIR = "/var/snap/opensearch/current"

    def __init__(self, charm, peer_relation: str):
        super().__init__(charm, peer_relation)

        cache = snap.SnapCache()
        self._opensearch = cache["opensearch"]

    @override
    def install(self):
        """Install opensearch from the snapcraft store."""
        if self._opensearch.present:
            return

        try:
            self._opensearch.ensure(snap.SnapState.Latest, channel="edge")
            self._opensearch.connect("opensearch:process-control")
        except SnapError as e:
            logger.error(f"Failed to install opensearch. \n{e}")
            raise OpenSearchInstallError()

    @override
    def _start_service(self):
        """Start the snap exposed "daemon" service."""
        if not self._opensearch.present:
            raise OpenSearchMissingError()

        if self._opensearch.services[self.SERVICE_NAME]["active"]:
            logger.info(f"The opensearch.{self.SERVICE_NAME} service is already started.")
            return

        try:
            self._opensearch.start([self.SERVICE_NAME])
        except SnapError as e:
            logger.error(f"Failed to start the opensearch.{self.SERVICE_NAME} service. \n{e}")
            raise OpenSearchStartError()

    @override
    def _stop_service(self):
        """Stop the snap exposed "daemon" service."""
        if not self._opensearch.present:
            raise OpenSearchMissingError()

        try:
            self._opensearch.stop([self.SERVICE_NAME])
        except SnapError as e:
            logger.error(f"Failed to stop the opensearch.{self.SERVICE_NAME} service. \n{e}")
            raise OpenSearchStopError()

    def is_failed(self) -> bool:
        """Check if snap service failed."""
        if not self._opensearch.present:
            raise OpenSearchMissingError()

        # TODO: replace with is_failed from lib once PR made to the lib.
        return _systemctl("is-failed", "snap.opensearch.daemon.service", quiet=True)

    @override
    def _build_paths(self) -> Paths:
        """Builds a Path object.

        The main paths are:
          - OPENSEARCH_HOME: read-only path ($SNAP/..), where the opensearch binaries are
          - OPENSEARCH_CONF: writeable by root or snap_daemon ($SNAP_COMMON) where config files are
        """
        return Paths(
            home=f"{self._BASE_SNAP_DIR}/current",
            conf=f"{self._BASE_SNAP_DIR}/common/config",
            data=f"{self._BASE_SNAP_DIR}/common/data",
            logs=f"{self._BASE_SNAP_DIR}/common/logs",
            jdk=f"{self._BASE_SNAP_DIR}/current/jdk",
            tmp=f"{self._BASE_SNAP_DIR}/common/tmp",
        )


class OpenSearchTarball(OpenSearchDistribution):
    """Tarball distro of opensearch, only overrides properties and logic proper to the tar."""

    def __init__(self, charm, peer_relation: str):
        super().__init__(charm, peer_relation)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    @override
    def install(self):
        """Temporary (will be deleted later) - Download and Un-tar the opensearch distro."""
        url = "https://artifacts.opensearch.org/releases/bundle/opensearch/2.6.0/opensearch-2.6.0-linux-x64.tar.gz"
        try:
            response = requests.get(url)

            tarball_path = "opensearch.tar.gz"
            with open(tarball_path, "wb") as f:
                f.write(response.content)
        except Exception as e:
            logger.error(e)
            raise OpenSearchInstallError()

        extract_tarball(tarball_path, self.paths.home)
        self._create_systemd_unit()

    @override
    def _start_service(self):
        """Start opensearch."""
        try:
            self._setup_linux_perms()
            self._run_cmd(
                "setpriv",
                "--clear-groups --reuid ubuntu --regid ubuntu -- sudo systemctl start opensearch.service",
            )
        except OpenSearchCmdError:
            raise OpenSearchStartError()

    @override
    def _stop_service(self):
        """Stop opensearch."""
        try:
            self._run_cmd("systemctl stop opensearch.service")
        except OpenSearchCmdError:
            logger.debug("Failed stopping the opensearch service.")
            raise OpenSearchStopError()

        start = datetime.now()
        while self.is_started() and (datetime.now() - start).seconds < 60:
            time.sleep(3)

    @override
    def is_failed(self) -> bool:
        """Check if the opensearch daemon has failed."""
        # TODO: replace with is_failed from lib once PR made to the lib.
        return _systemctl("is-failed", "opensearch.service", quiet=True)

    @override
    def _build_paths(self) -> Paths:
        return Paths(
            home="/etc/opensearch",
            conf="/etc/opensearch/config",
            data="/mnt/opensearch/data",
            logs="/mnt/opensearch/logs",
            jdk="/etc/opensearch/jdk",
            tmp="/mnt/opensearch/tmp",
        )

    def _setup_linux_perms(self):
        """Create ubuntu:ubuntu user:group."""
        self._run_cmd("chown", f"-R ubuntu:ubuntu {self.paths.home}")
        self._run_cmd("chown", "-R ubuntu:ubuntu /mnt/opensearch")

    def _create_systemd_unit(self):
        """Create a systemd unit file to run OpenSearch as a service."""
        env_variables = ""
        for key, val in os.environ.items():
            if key.startswith("OPENSEARCH"):
                env_variables = f"{env_variables}Environment={key}={val}\n"

        unit_content = f"""[Unit]
        Description=OpenSearch Service

        [Service]
        User=ubuntu
        Group=ubuntu
        ExecStart={self.paths.home}/bin/opensearch
        LimitNOFILE=65536:1048576
        {env_variables}

        [Install]
        WantedBy=multi-user.target
        """

        self.write_file(
            "/etc/systemd/system/opensearch.service",
            "\n".join([line.strip() for line in unit_content.split("\n")]),
        )

        self._run_cmd("systemctl daemon-reload")
