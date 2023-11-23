# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
"""COS integration """

import logging

from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.opensearch.v0.constants_charm import COSRelationName
from charms.opensearch.v0.opensearch_exceptions import OpenSearchError
from charms.opensearch.v0.opensearch_plugins import (
    OpenSearchPluginError,
)

from ops.framework import EventBase, EventSource
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.charm import CharmEvents
from ops import RelationCreatedEvent, RelationDepartedEvent


logger = logging.getLogger(__name__)

# The unique Charmhub library identifier, never change it
LIBID = "dcc76298a3a5435fb9a23e4d60b1bcbe"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class COSRelationDisappearedEvent(EventBase):
    """Anevent emmitted after the relation has disappearad from Juju"""


class OpenSearchCOSEvents(CharmEvents):

    relation_disappeared = EventSource(COSRelationDisappearedEvent)


class OpenSearchCOSProvider(COSAgentProvider):
    """COS integration -- specific to OpenSearch."""

    on = OpenSearchCOSEvents()

    def __init__(self, charm, *args, **kwargs):
        super().__init__(charm, *args, **kwargs)
        self.charm = charm

        self.charm.framework.observe(
            getattr(self.on, "relation_disappeared"),
            self._on_cos_agent_relation_disappeared
        )

    def _on_cos_agent_relation_created(self, event: RelationCreatedEvent):
        try:
            if self.charm.plugin_manager.run():
                self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
                    callback_override="_restart_opensearch"
                )
        except OpenSearchError as e:
            if isinstance(e, OpenSearchPluginError):
                self.charm.unit.status = WaitingStatus("s3-changed: cluster not ready yet")
            else:
                self.charm.unit.status = BlockedStatus(
                    "Unexpected error during plugin configuration, check the logs"
                )
                # There was an unexpected error, log it and block the unit
                logger.error(e)
            event.defer()
        self.charm.unit.status = ActiveStatus()

    def _on_cos_agent_relation_departed(self, event: RelationDepartedEvent):
        """Emit custom event AFTER the cos relation is gone."""
        if event.relation.name == COSRelationName:
            getattr(self.on, "relation_disappeared").emit()

    def _on_cos_agent_relation_disappeared(self, event: RelationDepartedEvent):
        """Re-run plugin configuration is the cos relation is not present anymore"""
        try:
            if self.charm.plugin_manager.run():
                self.charm.on[self.charm.service_manager.name].acquire_lock.emit(
                    callback_override="_restart_opensearch"
                )
        except OpenSearchError as e:
            if isinstance(e, OpenSearchPluginError):
                self.charm.unit.status = WaitingStatus("s3-changed: cluster not ready yet")
            else:
                self.charm.unit.status = BlockedStatus(
                    "Unexpected error during plugin configuration, check the logs"
                )
                # There was an unexpected error, log it and block the unit
                logger.error(e)
            event.defer()
        self.charm.unit.status = ActiveStatus()
