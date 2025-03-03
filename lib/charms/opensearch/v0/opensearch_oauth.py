#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module tasked with handling OpenSearch OAuth configuration."""

import logging
from typing import TYPE_CHECKING

from charms.hydra.v0.oauth import ClientConfig, OAuthRequirer
from charms.opensearch.v0.constants_charm import OAUTH_RELATION
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops import EventBase, Object

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

logger = logging.getLogger(__name__)


class OAuthHandler(Object):
    """Handler for managing oauth relations."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, "oauth")
        self.charm = charm

        # NOTE: Placeholder config options, not really needed by Opensearch
        client_config = ClientConfig(
            redirect_uri="http://opensearch.local",
            scope="openid email profile",
            grant_types=["client_credentials"],
        )
        self.oauth = OAuthRequirer(self.charm, client_config, relation_name=OAUTH_RELATION)
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_changed, self._on_oauth_relation_changed
        )
        self.framework.observe(
            self.charm.on[OAUTH_RELATION].relation_broken, self._on_oauth_relation_changed
        )

    def _on_oauth_relation_changed(self, event: EventBase) -> None:
        """Handler for `_on_oauth_relation_changed` event.

        Updates the security config.yml with the OIDC info and update the cluster.
        """
        if not (provider_info := self.oauth.get_provider_info()):
            return

        if (
            self.charm.unit.is_leader()
            # First wait until "normal" initialization is finished
            and self.charm.peers_data.get(Scope.APP, "security_index_initialised")
            and "data" in self.charm.opensearch_peer_cm.deployment_desc().config.roles
        ):
            self.charm.opensearch_config.add_oidc_auth(
                openid_connect_url=f"{provider_info.issuer_url}/.well-known/openid-configuration"
            )

            admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
            try:
                self.charm.update_security_config(admin_secrets)

            except OpenSearchCmdError as e:
                logger.debug(f"Error when updating the security index: {e.out}")
                event.defer()
                return
