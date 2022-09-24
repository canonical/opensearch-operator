# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class we manage opensearch distributions specific to the VM charm.

This class handles install / start / stop of opensearch services.
It also exposes some properties and methods for interacting with an OpenSearch Installation
"""

import logging
import tarfile

from charms.opensearch.v0.opensearch_distro import (
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
            self._run_cmd(f"snap connect opensearch:{plug}", cmd_has_args=True)

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
        )


class OpenSearchTarball(OpenSearchDistribution):
    """Snap distribution of opensearch, only overrides properties and logic proper to the snap."""

    def __init__(self, charm, peer_relation: str):
        super().__init__(charm, peer_relation)

    def install(self):
        """Un-tar the opensearch distro located in the charm/resources folder."""
        with tarfile.open("resources/opensearch.tar.gz") as tar:
            tar.extractall(self.paths.home)

    def start(self):
        """Start opensearch as a Daemon."""
        self.run_bin("opensearch", "--daemonize")

    def stop(self):
        """Stop opensearch."""  # TODO gracefully
        self._run_cmd("ps aux | grep opensearch | xargs '{print $2}' | kill -9")

    def restart(self):
        """Restart opensearch."""
        self.stop()
        self.start()

    def _build_paths(self) -> Paths:
        return Paths(
            home="/etc/opensearch",
            conf="/etc/opensearch/config",
            data="/mnt/opensearch/data",
            logs="/mnt/opensearch/logs",
        )
