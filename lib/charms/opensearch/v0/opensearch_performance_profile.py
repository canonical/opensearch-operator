# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Represents the performance profile of the OpenSearch cluster.

The main goals of this library is to provide a way to manage the performance
profile of the OpenSearch cluster.

There are two ways the charm can learn about its profile and when it changes:
1) If this is the MAIN_ORCHESTRATOR: config-changed -> the user has switched the profile directly
2) If not the MAIN_ORCHESTRATOR: peer-cluster-relation-changed -> the main orchestrator has
                                 switched the profile

The charm will then apply the profile and restart the OpenSearch service if needed.
"""
import logging

import ops
from charms.opensearch.v0.constants_charm import PERFORMANCE_PROFILE
from charms.opensearch.v0.models import (
    DeploymentType,
    OpenSearchPerfProfile,
    PerformanceType,
)
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.framework import EventBase, EventSource

# The unique Charmhub library identifier, never change it
LIBID = "8b7aa39016e748ea908787df1d7fb089"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class _ApplyProfileTemplatesOpenSearch(EventBase):
    """Attempt to apply the profile templates.

    The main reason to have a separate event, is to be able to wait for the cluster to restart.
    In this case, deferring this event does not defer any major other event.
    """


class OpenSearchPerformance(ops.Object):
    """Base class for OpenSearch charms."""

    _apply_profile_templates_event = EventSource(_ApplyProfileTemplatesOpenSearch)

    def __init__(self, charm: ops.charm.CharmBase = None):
        super().__init__(charm, None)
        self.charm = charm
        self.peers_data = self.charm.peers_data
        self.framework.observe(
            self._apply_profile_templates_event, self._on_apply_profile_templates
        )
        self._apply_profile_templates_has_been_called = False

    @property
    def current(self) -> OpenSearchPerfProfile | None:
        """Return the current performance profile.

        The profile is saved as a string in the charm peer databag.
        """
        if not self.peers_data.get(Scope.UNIT, PERFORMANCE_PROFILE):
            return None
        return OpenSearchPerfProfile.from_dict(
            {"typ": self.peers_data.get(Scope.UNIT, PERFORMANCE_PROFILE)}
        )

    @current.setter
    def current(self, value: OpenSearchPerfProfile | str):
        """Set the current performance profile."""
        if isinstance(value, OpenSearchPerfProfile):
            value = value.typ
        elif isinstance(value, str):
            # Ensure the value is a valid one
            value = PerformanceType(value)

        self.peers_data.put(Scope.UNIT, PERFORMANCE_PROFILE, str(value))

    def apply(self, profile_name: str) -> bool:
        """Apply the performance profile.

        If returns True, then the caller must execute a restart.
        """
        logger.info(f"Current profile: {str(self.current)}, new proposed profile: {profile_name}")
        new_profile = OpenSearchPerfProfile.from_dict(
            {
                "typ": profile_name,
            }
        )
        if self.current == new_profile:
            # Nothing to do, nothing changes
            return False

        self.charm.opensearch_config.apply_performance_profile(new_profile)
        self.current = new_profile

        if self.charm.opensearch_peer_cm.deployment_desc().typ == DeploymentType.MAIN_ORCHESTRATOR:
            self._apply_profile_templates_event.emit()
        return True

    def _on_apply_profile_templates(self, event: EventBase):
        """Apply the profile templates.

        The main reason to have a separate event, is to be able to wait for the cluster. It
        defers otherwise and only defers the execution of this particular task.
        """
        logger.info("Applying profile-templates")
        if not self.charm.unit.is_leader():
            # Only the leader can apply the templates
            return

        if self._apply_profile_templates_has_been_called:
            # we can safely abandon this event as we already had a previous call on the same hook
            return
        self._apply_profile_templates_has_been_called = True

        if (
            not self.charm.opensearch_peer_cm.deployment_desc()
            or not self.charm.opensearch.is_node_up()
        ):
            logger.info("Applying profile templates but cluster not ready yet.")
            event.defer()
            return

        # Configure templates if needed
        if not self.apply_perf_templates_if_needed():
            logger.debug("Failed to apply templates. Will retry later.")
            event.defer()

    def apply_perf_templates_if_needed(  # noqa: C901
        self, new_profile: PerformanceType | None = None
    ) -> bool:
        """Apply performance templates if needed."""
        profile = new_profile or self.current.typ
        if not profile:
            return False

        if profile == PerformanceType.TESTING:
            # We try to remove the index and components' templates
            for endpoint in [
                "/_index_template/charmed-index-tpl",
            ]:
                try:
                    self.charm.opensearch.request("DELETE", endpoint)
                except OpenSearchHttpError as e:
                    if e.response_code != 404:
                        logger.warning(f"Failed to delete index template: {e}")
                        return False
            # Nothing to do anymore
            return True

        for idx, template in self.current.charmed_index_template.items():
            try:
                # We can re-run PUT on the same index template
                # It just gets updated and returns "ack: True"
                self.charm.opensearch.request("PUT", f"/_index_template/{idx}", template)
            except OpenSearchHttpError as e:
                logger.error(f"Failed to apply index template: {e}")
                return False

        for idx, template in self.current.charmed_component_templates.items():
            try:
                # We can re-run PUT on the same template
                # It just gets updated and returns "ack: True"
                self.charm.opensearch.request("PUT", f"/_component_template/{idx}", template)
            except OpenSearchHttpError as e:
                logger.error(f"Failed to apply component template: {e}")
                return False
        return True
