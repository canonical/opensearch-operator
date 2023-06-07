#!/usr/bin/env python3

# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed Machine Operator for OpenSearch."""
import logging

from charms.opensearch.v0.constants_charm import InstallError, InstallProgress
from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm
from charms.opensearch.v0.opensearch_exceptions import OpenSearchInstallError
from ops.charm import InstallEvent
from ops.main import main
from ops.model import BlockedStatus, MaintenanceStatus

from opensearch import OpenSearchSnap

logger = logging.getLogger(__name__)


class OpenSearchOperatorCharm(OpenSearchBaseCharm):
    """This class represents the machine charm for OpenSearch."""

    def __init__(self, *args):
        super().__init__(*args, distro=OpenSearchSnap)  # OpenSearchTarball

        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, _: InstallEvent) -> None:
        """Handle the install event."""
        self.unit.status = MaintenanceStatus(InstallProgress)
        try:
            self.opensearch.install()
            self.status.clear(InstallProgress)
        except OpenSearchInstallError:
            self.unit.status = BlockedStatus(InstallError)


if __name__ == "__main__":
    main(OpenSearchOperatorCharm)
