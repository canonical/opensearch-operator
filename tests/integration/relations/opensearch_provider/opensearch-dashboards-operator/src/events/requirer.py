#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handler for related applications on the `zookeeper` relation interface."""
import logging
from typing import TYPE_CHECKING

from charms.data_platform_libs.v0.data_interfaces import OpenSearchRequiresEventHandlers
from literals import OPENSEARCH_REL_NAME
from ops.charm import RelationBrokenEvent, RelationEvent
from ops.framework import Object

if TYPE_CHECKING:
    from charm import OpensearchDasboardsCharm

logger = logging.getLogger(__name__)


class RequirerEvents(Object):
    """Event handlers for related applications on the `zookeeper` relation interface."""

    def __init__(self, charm):
        super().__init__(charm, "provider")
        self.charm: "OpensearchDasboardsCharm" = charm

        self.requirer_events = OpenSearchRequiresEventHandlers(
            self.charm, self.charm.state.client_requires_data
        )

        self.framework.observe(
            self.charm.on[OPENSEARCH_REL_NAME].relation_changed, self._on_client_relation_changed
        )
        self.framework.observe(
            self.charm.on[OPENSEARCH_REL_NAME].relation_broken, self._on_client_relation_broken
        )

    def _on_client_relation_changed(self, event: RelationEvent) -> None:
        """Updates ACLs while handling `client_relation_changed` events."""
        if not self.charm.state.stable:
            event.defer()
            return

        if (
            self.charm.state.opensearch_server
            and self.charm.state.opensearch_server.username
            and self.charm.state.opensearch_server.password
            and self.charm.state.opensearch_server.endpoints
            and self.charm.state.opensearch_server.tls_ca
        ):
            self.charm.workload.write(
                content=self.charm.state.opensearch_server.tls_ca,
                path=self.charm.workload.paths.opensearch_ca,
            )
            self.charm.on.config_changed.emit()

    def _on_client_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Restoring config to defaults if the relation is gone.

        Args:
            event: used for passing `RelationBrokenEvent` to subsequent methods
        """
        # Don't remove anything if ZooKeeper is going down
        if self.charm.app.planned_units == 0 or not self.charm.unit.is_leader():
            return

        # call normal updated handler
        self._on_client_relation_changed(event=event)
