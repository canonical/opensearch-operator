# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class we manage opensearch distributions specific to the VM charm.

This class handles install / start / stop of opensearch services.
It also exposes some properties and methods for interacting with an OpenSearch Installation
"""

import logging
import time

import requests
from charms.opensearch.v0.opensearch_distro import (
    OpenSearchCmdError,
    OpenSearchDistribution,
    OpenSearchInstallError,
    OpenSearchMissingError,
    OpenSearchRestartError,
    OpenSearchStartError,
    OpenSearchStopError,
    Paths,
)
from charms.operator_libs_linux.v1 import snap
from charms.operator_libs_linux.v1.snap import SnapError
from tenacity import retry, stop_after_attempt, wait_exponential

from utils import extract_tarball

logger = logging.getLogger(__name__)


class OpenSearchSnap(OpenSearchDistribution):
    """Snap distribution of opensearch, only overrides properties and logic proper to the snap."""

    def __init__(self, charm, peer_relation: str):
        super().__init__(charm, peer_relation)

        cache = snap.SnapCache()
        self._opensearch = cache["opensearch"]

    def install(self):
        """Install opensearch from the snapcraft store."""
        if self._opensearch.present:
            return

        try:
            self._opensearch.ensure(snap.SnapState.Latest, channel="edge")
        except SnapError as e:
            logger.error(f"Failed to install opensearch. \n{e}")
            raise OpenSearchInstallError()

        plugs = [
            "log-observe",
            "mount-observe",
            "process-control",
            "procsys-read",
            "system-observe",
        ]
        for plug in plugs:
            self._run_cmd(f"snap connect opensearch:{plug}")

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

    def stop(self):
        """Stop the snap exposed "daemon" service."""
        if not self._opensearch.present:
            raise OpenSearchMissingError()

        try:
            self._opensearch.stop([self.SERVICE_NAME])
        except SnapError as e:
            logger.error(f"Failed to stop the opensearch.{self.SERVICE_NAME} service. \n{e}")
            raise OpenSearchStopError()

    def restart(self):
        """Restart the snap exposed "daemon" service."""
        if not self._opensearch.present:
            raise OpenSearchMissingError()

        try:
            self._opensearch.restart([self.SERVICE_NAME])
        except SnapError as e:
            logger.error(f"Failed to restart the opensearch.{self.SERVICE_NAME} service. \n{e}")
            raise OpenSearchRestartError()

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
    def install(self):
        """Temporary (will be deleted later) - Download and Un-tar the opensearch distro."""
        try:
            response = requests.get(
                "https://artifacts.opensearch.org/releases/bundle/opensearch/2.3.0/opensearch-2.3.0-linux-x64.tar.gz"
            )

            tarball_path = "opensearch.tar.gz"
            with open(tarball_path, "wb") as f:
                f.write(response.content)
        except Exception as e:
            logger.error(e)
            raise OpenSearchInstallError()

        extract_tarball(tarball_path, self.paths.home)

    def start(self):
        """Start opensearch as a Daemon."""
        logger.debug("Starting opensearch.")
        if self.is_started():
            return

        try:
            self._setup_linux_perms()
            self._run_cmd(
                "setpriv",
                f"--clear-groups --reuid ubuntu --regid ubuntu -- {self.paths.home}/bin/opensearch --daemonize",
            )
        except OpenSearchCmdError:
            raise OpenSearchStartError()

        if not self.is_started():
            raise OpenSearchStartError()

    def stop(self):
        """Stop opensearch."""
        self._run_cmd("pkill -15 opensearch")

        while self.is_node_up():
            time.sleep(2)

        """
        TODO:
            Important! Before you stop a node, you should ensure that no indexing requests or
            administration-related tasks are being made on the cluster. If you stop a node during
            indexing, the cluster meta data might get corrupted and the cluster could become
            non-operational (red color code). To ensure that no instances of PTSF_GENFEED are
            running, check the Process Monitor. If all processes are finished, you may stop
            all the nodes in a cluster and make the required modifications.
            After completing the modifications, you may start all the nodes of the cluster."""

    def restart(self):
        """Restart opensearch."""
        if self.is_started():
            self.stop()

        self.start()

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
