# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch client relation hooks & helpers.

TODO add databag reference
"""

import logging

from charms.data_platform_libs.v0.database_interfaces import DatabaseProvides
from charms.opensearch.v0.constants_charm import ClientRelationName
from ops.charm import CharmBase
from ops.framework import Object

logger = logging.getLogger(__name__)


class OpenSearchProvider(Object):
    """Defines functionality for the 'provides' side of the 'pgbouncer-client' relation.

    Hook events observed:
        - database-requested
        - relation-broken
    """

    def __init__(self, charm: CharmBase, relation_name: str = ClientRelationName) -> None:
        """Constructor for PgbouncerProvider object.

        Args:
            charm: the charm for which this relation is provided
            relation_name: the name of the relation
        """
        super().__init__(charm, relation_name)

        self.charm = charm
        self.relation_name = relation_name
        self.database_provides = DatabaseProvides(self.charm, relation_name=self.relation_name)

        self.framework.observe(
            self.database_provides.on.database_requested, self._on_database_requested
        )
        self.framework.observe(
            charm.on[self.relation_name].relation_broken, self._on_relation_broken
        )

    def _on_database_requested(self, _) -> None:
        """Handle client database-requested event."""

    def _on_relation_broken(self, _) -> None:
        """Handle client relation-broken event."""
