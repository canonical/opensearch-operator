# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch client relation hooks & helpers.

TODO add databag reference information
TODO move to charm lib

Databag needs client credentials and client cert
"""

import logging

from charms.data_platform_libs.v0.data_interfaces import DatabaseProvides
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
        # check app is ready to roll
        # application provides dbname, and extra-user-roles
        # dbname is called index in opensearch, can we change field name?
        # TLS cert can be provided by the client

        # generate db
        # generate user with roles

        # Provide endpoints, password, username, and version to application charm
        # readonly endpoints are not necessary

        # TODO don't do this now - for now, just generate one from TLS charm.
        # if we don't receive a cert in databag, then generate one.

        # Request unique cert from TLS charm of specific client type (todo), get from relation,
        # send in relation data
        # OR receive cert in action
        # OR receive cert in http requests, and skip generating one

        # FINAL
        # Receive request for given permissions
        # create TLS cert
        # create user with those perms and cert
        # provide user and TLS in relation

    def _on_relation_broken(self, _) -> None:
        """Handle client relation-broken event."""
        # check app is ready to roll
        # deauth user
        # del cert
