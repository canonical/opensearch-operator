# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class, we manage backup configurations and actions.

This class must load the opensearch plugin: s3-repository; and configure it.
"""

import logging

from charms.data_platform_libs.v0.s3 import CredentialsChangedEvent, S3Requirer
from ops.framework import Object

from lib.charms.opensearch.v0.opensearch_distro import OpenSearchDistribution

# The unique Charmhub library identifier, never change it
LIBID = "d704d9bd5688480a9cf408d62cff3bcb"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)

OPENSEARCH_SNAP_DATA_DIR = "/var/snap/opensearch/common/"

S3_RELATION = "s3-credentials"


class ResyncError(Exception):
    """Raised when pbm is resyncing configurations and is not ready to be used."""


class SetBackupConfigError(Exception):
    """Raised when pbm cannot configure a given option."""


class BackupBusyError(Exception):
    """Raised when PBM is busy and cannot run another operation."""


class OpenSearchBackups(Object):
    """In this class, we manage OpenSearch backups."""

    def __init__(self, charm, distro: OpenSearchDistribution):
        """Manager of OpenSearch client relations."""
        super().__init__(charm)
        self.charm = charm
        self.distro = distro

        # s3 relation handles the config options for s3 backups
        self.s3_client = S3Requirer(self.charm, S3_RELATION)
        # Used to ensure s3-repository plugin is loaded
        self.framework.observe(
            self.charm.on[S3_RELATION].relation_joined, self._on_s3_credential_joined
        )
        self.framework.observe(
            self.charm.on[S3_RELATION].relation_departed, self._on_s3_credential_departed
        )

        self.framework.observe(
            self.s3_client.on.credentials_changed, self._on_s3_credential_changed
        )
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_action)

    def _on_s3_credential_joined(self, _):
        """Loads the s3 plugin."""
        self.distro.add_plugin_without_restart("s3-repository")

    def _on_s3_credential_departed(self, _):
        """Unloads the s3 plugin."""
        self.distro.remove_plugin_without_restart("s3-repository")

    def _on_s3_credential_changed(self, event: CredentialsChangedEvent):
        """Sets credentials, resyncs if necessary and reports config errors."""
        self.distro.config.set_s3_parameters()
        self.on[self.charm.service_manager.name].acquire_lock.emit(
            callback_override="self.charm._restart_opensearch"
        )

    def _on_create_backup_action(self, event) -> None:
        pass

    def _on_list_backups_action(self, event) -> None:
        pass

    def _on_restore_action(self, event) -> None:
        pass
