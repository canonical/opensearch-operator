# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""COS integration."""

import logging

from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.opensearch.v0.opensearch_exceptions import OpenSearchError
from charms.opensearch.v0.opensearch_plugins import OpenSearchPluginError
from ops import EventBase, RelationBrokenEvent, RelationCreatedEvent
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

logger = logging.getLogger(__name__)

# The unique Charmhub library identifier, never change it
LIBID = "dcc76298a3a5435fb9a23e4d60b1bcbe"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class OpenSearchCOSProvider(COSAgentProvider):
    """COS integration -- specific to OpenSearch."""

    def __init__(self, charm, *args, **kwargs):
        super().__init__(charm, *args, **kwargs)

    def _run_plugin_manager(self, event: EventBase):
        """Execute plugin manager and handle prossible errors."""
        if not self._charm.unit.is_leader():
            return
        try:
            if self._charm.plugin_manager.run():
                self._charm.on[self._charm.service_manager.name].acquire_lock.emit(
                    callback_override="_restart_opensearch"
                )
        except OpenSearchError as e:
            if isinstance(e, OpenSearchPluginError):
                self._charm.unit.status = WaitingStatus("Cluster not ready yet")
            else:
                self._charm.unit.status = BlockedStatus(
                    "Unexpected error during plugin configuration, check the logs"
                )
                # There was an unexpected error, log it and block the unit
                logger.error(e)
            event.defer()
        self._charm.unit.status = ActiveStatus()

    def _on_cos_agent_relation_created(self, event: RelationCreatedEvent):
        """COS workflow initialization happens when the COS relation is created."""
        self._run_plugin_manager(event)

    def _on_cos_agent_relation_broken(self, event: RelationBrokenEvent):
        """Re-run plugin configuration is the cos relation is not present anymore."""
        if self._charm.model.get_relation("cos-agent"):
            event.defer()
            return
        self._run_plugin_manager(event)
