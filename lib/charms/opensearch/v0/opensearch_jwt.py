# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for everything related to OpenSearch JWT authentication configuration."""

import logging
from typing import TYPE_CHECKING

import ops
from charms.data_platform_libs.v0.data_interfaces import RequirerData
from charms.opensearch.v0.constants_charm import (
    JWT_CONFIG_RELATION,
    JWTAuthConfigInvalid,
    JWTRelationInvalid,
    SecurityIndexUpdateError,
)
from charms.opensearch.v0.constants_tls import CertType
from charms.opensearch.v0.models import DeploymentType, JWTAuthConfiguration
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.opensearch.v0.opensearch_internal_data import Scope
from pydantic.error_wrappers import ValidationError

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

# The unique Charmhub library identifier, never change it
LIBID = "c6eab0abbd8b426fa99421c9460e2bc9"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class JwtConfigurationRequires(RequirerData):
    """Data Interface to JWT relation on requirer side."""

    def __init__(self, model, relation_name: str):
        super().__init__(
            model,
            relation_name,
            additional_secret_fields=["signing-key"],
        )


class JwtHandler(ops.Object):
    """Handler for managing JWT relations."""

    def __init__(self, charm: "OpenSearchBaseCharm") -> None:
        super().__init__(charm, "jwt")
        self.charm = charm

        self.jwt_requires = JwtConfigurationRequires(self.model, relation_name=JWT_CONFIG_RELATION)

        # --- EVENT HANDLERS ---
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)
        self.framework.observe(
            self.charm.on[JWT_CONFIG_RELATION].relation_created, self._on_jwt_relation_created
        )
        self.framework.observe(
            self.charm.on[JWT_CONFIG_RELATION].relation_changed, self._on_jwt_relation_changed
        )
        self.framework.observe(
            self.charm.on[JWT_CONFIG_RELATION].relation_broken, self._on_jwt_relation_broken
        )

    @property
    def jwt_relation(self) -> ops.Relation | None:
        """Return the jwt relation if present."""
        return self.jwt_requires.relations[0] if len(self.jwt_requires.relations) else None

    def _on_jwt_relation_created(self, event: ops.RelationCreatedEvent) -> None:
        """Handle relation creation."""
        if self.charm.opensearch_peer_cm.deployment_desc().typ != DeploymentType.MAIN_ORCHESTRATOR:
            # in large deployments, JWT configuration must only be handled by the main orchestrator
            # this is a safeguard to avoid different sources for applying security configuration
            if self.charm.unit.is_leader():
                self.charm.status.set(ops.BlockedStatus(JWTRelationInvalid), app=True)

    def _on_jwt_relation_changed(self, event: ops.RelationChangedEvent) -> None:
        """Handle changed relation data."""
        if self.charm.opensearch_peer_cm.deployment_desc().typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.set(ops.BlockedStatus(JWTRelationInvalid), app=True)
            return

        if not self.jwt_relation:
            logger.error(f"Cannot access relation data for {JWT_CONFIG_RELATION}")
            return

        relation_data = self.jwt_requires.fetch_relation_data([self.jwt_relation.id])
        jwt_config = relation_data[self.jwt_relation.id]

        self._validate_and_apply_jwt_auth_config(jwt_config)

    def _on_jwt_relation_broken(self, event: ops.RelationBrokenEvent) -> None:
        """Handle the removal of the relation."""
        if self.charm.opensearch_peer_cm.deployment_desc().typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.clear(JWTRelationInvalid, app=True)
            return

        self.charm.opensearch_config.unset_jwt_auth()

        try:
            self._update_security_index()
            logger.info("Updated Opensearch security index")
        except OpenSearchCmdError as e:
            logger.debug(f"Error when updating the security index: {e.out}")
            if self.charm.unit.is_leader():
                self.charm.status.set(ops.BlockedStatus(SecurityIndexUpdateError), app=True)
            # we need to come back in this case because there will not be a follow-up event
            event.defer()
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(SecurityIndexUpdateError, app=True)

    def _on_secret_changed(self, event: ops.SecretChangedEvent) -> None:
        """Handle changed secret data."""
        if not self.jwt_relation:
            return

        if self.charm.opensearch_peer_cm.deployment_desc().typ != DeploymentType.MAIN_ORCHESTRATOR:
            if self.charm.unit.is_leader():
                self.charm.status.set(ops.BlockedStatus(JWTRelationInvalid), app=True)
            return

        if not (relation := self.jwt_requires._relation_from_secret_label(event.secret.label)):
            logger.debug("Updated secret not relevant")
            return

        if event.secret.label != self.jwt_requires._generate_secret_label(
            relation.name,
            relation.id,
            "extra",
        ):
            logging.debug("Updated secret not relevant")
            return

        relation_data = self.jwt_requires.fetch_relation_data([self.jwt_relation.id])
        jwt_config = relation_data[self.jwt_relation.id]
        self._validate_and_apply_jwt_auth_config(jwt_config)

    def _validate_and_apply_jwt_auth_config(self, jwt_config: dict[str, str]) -> None:
        """Check the provided configuration and apply, if valid."""
        try:
            jwt_auth_config = JWTAuthConfiguration(
                signing_key=jwt_config.get("signing-key"),
                jwt_header=jwt_config.get("jwt-header"),
                jwt_url_parameter=jwt_config.get("jwt-url-parameter"),
                roles_key=jwt_config.get("roles-key"),
                subject_key=jwt_config.get("subject-key"),
                required_audience=jwt_config.get("required-audience"),
                required_issuer=jwt_config.get("required-issuer"),
                jwt_clock_skew_tolerance_seconds=jwt_config.get(
                    "jwt-clock-skew-tolerance-seconds"
                ),
            )
        except ValidationError as e:
            # safety mechanism, this should not happen; config is validated on the jwt-integrator
            logger.error(f"Validation failed for JWT authentication config: {e}")
            if self.charm.unit.is_leader():
                self.charm.status.set(ops.BlockedStatus(JWTAuthConfigInvalid), app=True)
            return

        self.charm.opensearch_config.set_jwt_auth(jwt_auth_config)
        logger.info("Updated JWT authentication configuration")

        try:
            self._update_security_index()
            logger.info("Updated Opensearch security index")
        except OpenSearchCmdError as e:
            logger.debug(f"Error when updating the security index: {e.out}")
            if self.charm.unit.is_leader():
                self.charm.status.set(ops.BlockedStatus(SecurityIndexUpdateError), app=True)
            return

        if self.charm.unit.is_leader():
            self.charm.status.clear(SecurityIndexUpdateError, app=True)
            self.charm.status.clear(JWTAuthConfigInvalid, app=True)

    def _update_security_index(self) -> None:
        """Update Opensearch's security index after updating the JWT auth configuration."""
        if not self.charm.unit.is_leader():
            return

        if not self.charm.peers_data.get(Scope.APP, "security_index_initialised", False):
            logger.debug("Security index has not been initialized, cannot update security config.")
            return

        logger.info("Updating security configuration")
        admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)

        self.charm.update_security_config(
            admin_secrets, self.charm.opensearch_config.SECURITY_CONFIG_YML
        )
