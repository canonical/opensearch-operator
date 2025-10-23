# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module tasked with handling OpenSearch OAuth configuration."""

import logging
from typing import TYPE_CHECKING

from charms.hydra.v0.oauth import ClientConfig, OAuthRequirer
from charms.opensearch.v0.constants_charm import OAUTH_RELATION, OAuthRelationInvalid
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.models import DeploymentType
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import (
    BlockedStatus,
    EventBase,
    Object,
    RelationBrokenEvent,
    RelationCreatedEvent,
    RelationDepartedEvent,
)

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

# The unique Charmhub library identifier, never change it
LIBID = "c761774d45d8494fb3601addc7676d0e"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OAuthHandler(Object):
    """Handler for managing oauth relations."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, "oauth")
        self.charm = charm

        # NOTE: Placeholder config options, not really needed by Opensearch
        client_config = ClientConfig(
            audience=["opensearch"],
            redirect_uri="http://opensearch.local",
            scope="openid email profile",
            grant_types=["client_credentials"],
        )
        self.oauth = OAuthRequirer(self.charm, client_config, relation_name=OAUTH_RELATION)
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_created,
            self._on_oauth_relation_created,
        )
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_changed,
            self._on_oauth_relation_changed,
        )
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_departed,
            self._on_oauth_relation_departed,
        )
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_broken,
            self._on_oauth_relation_broken,
        )

    def _on_oauth_relation_created(self, event: RelationCreatedEvent) -> None:
        """Handler for `relation_created` event."""
        if self.charm.opensearch_peer_cm.deployment_desc().typ != DeploymentType.MAIN_ORCHESTRATOR:
            # in large deployments, OAuth config must only be handled by the main orchestrator
            # this is a safeguard to avoid different sources for applying security configuration
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(OAuthRelationInvalid), app=True)

    def _on_oauth_relation_changed(self, event: EventBase) -> None:
        """Handler for `_on_oauth_relation_changed` event.

        Updates the security config.yml with the OIDC info and update the cluster.
        """
        if self.charm.opensearch_peer_cm.deployment_desc().typ != DeploymentType.MAIN_ORCHESTRATOR:
            # in large deployments, OAuth config must only be handled by the main orchestrator
            # this is a safeguard to avoid different sources for applying security configuration
            if self.charm.unit.is_leader():
                self.charm.status.set(BlockedStatus(OAuthRelationInvalid), app=True)
            return

        relation = self.model.get_relation(OAUTH_RELATION)
        if not relation.data[relation.app]:
            logger.debug("Oauth relation not yet set up")
            return

        if not self._is_unit_ready():
            logger.debug("Deferring oauth relation changed event as cluster is not ready yet")
            event.defer()
            return

        self.charm.opensearch_config.add_oidc_auth(
            openid_connect_url=f"{relation.data[relation.app].get('issuer_url')}/.well-known/openid-configuration"
        )

        if not self.charm.unit.is_leader():
            return

        if not (admin_secrets := self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)):
            event.defer()
            return
        try:
            self.charm.update_security_config(
                admin_secrets, self.charm.opensearch_config.SECURITY_CONFIG_YML
            )
        except OpenSearchCmdError as e:
            logger.debug(f"Error when updating the security index: {e.out}")
            event.defer()
            return

    def _on_oauth_relation_departed(self, event: RelationDepartedEvent) -> None:
        """Handler for `relation_departed` event."""
        if event.departing_unit == self.charm.unit and self.charm.peers_data is not None:
            self.charm.peers_data.put(Scope.UNIT, "departing_oauth", True)

    def _on_oauth_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handler for `relation_broken` event."""
        if self.charm.opensearch_peer_cm.deployment_desc().typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.clear(OAuthRelationInvalid, app=True)
            return

        if (
            self.charm.peers_data is None
            or self.charm.peers_data.get(Scope.UNIT, "departing_oauth")
            or not self._is_unit_ready()
        ):
            return

        self.charm.opensearch_config.remove_oidc_auth()

        if not self.charm.unit.is_leader():
            return

        if not (admin_secrets := self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)):
            event.defer()
            return
        try:
            self.charm.update_security_config(
                admin_secrets, self.charm.opensearch_config.SECURITY_CONFIG_YML
            )
        except OpenSearchCmdError as e:
            logger.debug(f"Error when updating the security index: {e.out}")
            event.defer()
            return

    def _is_unit_ready(self) -> bool:
        return bool(self.charm.opensearch_peer_cm.deployment_desc()) and bool(
            self.charm.peers_data.get(Scope.APP, "security_index_initialised")
        )
