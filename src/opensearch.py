# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class we manage opensearch distributions specific to the VM charm.

This class handles install / start / stop of opensearch services.
It also exposes some properties and methods for interacting with an OpenSearch Installation
"""

import logging
import os
import time

import requests
from charms.opensearch.v0.opensearch_distro import (
    OpenSearchCmdError,
    OpenSearchDistribution,
    OpenSearchInstallError,
    OpenSearchMissingError,
    OpenSearchStartError,
    OpenSearchStopError,
    Paths,
)
from charms.operator_libs_linux.v1 import snap
from charms.operator_libs_linux.v1.snap import SnapError
from overrides import override
from tenacity import retry, stop_after_attempt, wait_exponential

from utils import extract_tarball

logger = logging.getLogger(__name__)


class OpenSearchSnap(OpenSearchDistribution):
    """Snap distribution of opensearch, only overrides properties and logic proper to the snap."""

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
        except SnapError as e:
            logger.error(f"Failed to install opensearch. \n{e}")
            raise OpenSearchInstallError()

        self._run_cmd("snap connect opensearch:process-control")

    @override
    def start(self):
        """Start the snap exposed "daemon" service."""
        if not self._opensearch.present:
            raise OpenSearchMissingError()

        if self._opensearch.services[self.SERVICE_NAME]["active"]:
            logger.info(
                f"Not doing anything, the opensearch.{self.SERVICE_NAME} service is already started."
            )
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

    @override
    def _build_paths(self) -> Paths:
        """Builds a Path object.

        The main paths are:
          - OPENSEARCH_HOME: read-only path ($SNAP/..), where the opensearch binaries are
          - OPENSEARCH_CONF: writeable by root or snap_daemon ($SNAP_COMMON) where config files are
        """
        return Paths(
            home="/var/snap/opensearch/current",
            conf="/var/snap/opensearch/common/config",
            data="/var/snap/opensearch/common/data",
            logs="/var/snap/opensearch/common/logs",
            jdk="/var/snap/opensearch/current/jdk",
            tmp="/var/snap/opensearch/common/tmp",
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
        try:
            response = requests.get(
                "https://artifacts.opensearch.org/releases/bundle/opensearch/2.4.0/opensearch-2.4.0-linux-x64.tar.gz"
            )

            tarball_path = "opensearch.tar.gz"
            with open(tarball_path, "wb") as f:
                f.write(response.content)
        except Exception as e:
            logger.error(e)
            raise OpenSearchInstallError()

        extract_tarball(tarball_path, self.paths.home)
        self._create_systemd_unit()

    @override
    def start(self):
        """Start opensearch as a Daemon."""
        logger.debug("Starting opensearch.")
        if self.is_started():
            return

        try:
            self._setup_linux_perms()
            self._run_cmd(
                "setpriv",
                "--clear-groups --reuid ubuntu --regid ubuntu -- sudo systemctl start opensearch.service",
            )
        except OpenSearchCmdError:
            raise OpenSearchStartError()

        retries = 0
        while not self.is_started() and retries < 3:
            time.sleep(2)
            retries += 1
        else:
            raise OpenSearchStartError()

    @override
    def _stop_service(self):
        """Stop opensearch."""
        self._run_cmd(
            "setpriv",
            "--clear-groups --reuid ubuntu --regid ubuntu -- sudo systemctl stop opensearch.service",
        )

        retries = 0
        while retries < 3:
            if not self.is_started():
                return

            time.sleep(2)
            retries += 1

        raise OpenSearchStopError()

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
