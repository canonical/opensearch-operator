# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class we manage certificates relation.

This class handles certificate request and renewal through
the interaction with the TLS Certificates Operator.

This library needs https://charmhub.io/tls-certificates-interface/libraries/tls_certificates
library is imported to work.

It requires a charm that extends OpenSearchBaseCharm as it refers internal objects of that class.
— update_config: to disable TLS when relation with the TLS Certificates Operator is broken.
"""

import logging

from charms.opensearch.v0.constants_charm import Scope
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.opensearch_internal_data import SecretsDataStore
from ops.charm import ActionEvent
from ops.framework import Object

# The unique Charmhub library identifier, never change it
LIBID = "8bcf275287ad486db5f25a1dbb26f920"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OpenSearchSecrets(Object, SecretsDataStore):
    """Encapsulating Juju3 secrets handling."""

    def __init__(self, charm, peer_relation: str):
        Object.__init__(self, charm, peer_relation)
        SecretsDataStore.__init__(self, charm, peer_relation)

        self.charm = charm
        self.peer_relation = peer_relation

        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_secret_changed(self, event: ActionEvent):
        """Refresh secret and re-run corresponding actions if needed."""
        if not event.secret.label:
            logger.info("Secret %s has no label, ignoring it", event.secret.id)

        label_parts = self.breakdown_label(event.secret.label)
        if (
            label_parts["application_name"] == self.charm.app.name
            and label_parts["scope"] == Scope.APP
            and label_parts["key"] == CertType.APP_ADMIN.val
        ):
            scope = Scope.APP
        else:
            logger.info("Secret %s was not relevant for us.", event.secret.label)
            return

        logger.debug("Secret change for %s, %s", scope, label_parts["key"])

        if not self.charm.unit.is_leader():
            self.charm.store_tls_resources(CertType.APP_ADMIN, event.secret.get_content())
