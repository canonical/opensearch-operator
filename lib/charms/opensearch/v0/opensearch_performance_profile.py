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
from charms.opensearch.v0.constants_charm import (
    PERFORMANCE_PROFILE,
    PeerClusterRelationName,
)
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
    """Attempt to acquire lock & restart OpenSearch.

    The main reason to have a separate event, is to be able to wait for the cluster.
    It defers otherwise and only defers the execution of this particular task.
    """


class OpenSearchPerformance(ops.Object):
    """Base class for OpenSearch charms."""

    _apply_profile_templates_event = EventSource(_ApplyProfileTemplatesOpenSearch)

    def __init__(self, charm: ops.charm.CharmBase = None):
        super().__init__(charm, None)
        self.charm = charm
        self.peers_data = self.charm.peers_data

        self.framework.observe(
            charm.on.install,
            self._on_install,
        )
        self.framework.observe(
            charm.on[PeerClusterRelationName].relation_changed,
            self._on_peer_cluster_relation_changed,
        )
        self.framework.observe(
            self._apply_profile_templates_event, self._on_apply_profile_templates
        )
        self._apply_profile_templates_has_been_called = False

    def _on_install(self, _):
        """Handle install event.

        Execute it on install, as defined in the docs, it is the first hook to run:
           https://juju.is/docs/sdk/config-changed-event

        install -> config-changed -> start

        Store the current perf. profile we are applying. This must happen solely
        on the beginning of the charm lifecycle. Therefore, we check if the unit is down.
        """
        self.apply(self.charm.config.get(PERFORMANCE_PROFILE))

    def _on_peer_cluster_relation_changed(self, _: EventBase):
        """Handle the peer cluster relation changed event."""
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            # Deployment description not available yet
            # Nothing to do
            return

        if self.apply(deployment_desc.performance_profile):
            # We need to restart
            self.charm.restart_event.emit()

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
        new_profile = OpenSearchPerfProfile.from_dict(
            {
                "typ": profile_name,
            }
        )
        if self.current == new_profile:
            # Nothing to do, nothing changes
            return False

        self.charm.opensearch_config.apply_performance_profile(new_profile)
        self._apply_profile_templates_event.emit()
        self.current = new_profile
        return True

    def _on_apply_profile_templates(self, event: EventBase):
        """Apply the profile templates.

        The main reason to have a separate event, is to be able to wait for the cluster. It
        defers otherwise and only defers the execution of this particular task.
        """
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

        if (
            self.charm.opensearch_peer_cm.deployment_desc().typ != DeploymentType.MAIN_ORCHESTRATOR
            and not self.charm.unit.is_leader()
        ):
            return

        # Configure templates if needed
        if not self.charm.opensearch.apply_perf_templates_if_needed():
            logger.debug("Failed to apply templates. Will retry later.")
            event.defer()

    def apply_perf_templates_if_needed(self) -> bool:  # noqa: C901
        """Apply performance templates if needed."""
        if self.current.typ == PerformanceType.TESTING:
            # We try to remove the index and components' templates
            for endpoint in [
                "/_index_template/charmed-index-tpl",
            ]:
                try:
                    self.charm.opensearch.request("DELETE", endpoint)
                except OpenSearchHttpError as e:
                    if e.response_code == 404:
                        # Nothing to do, this error means the template does not exist
                        pass
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
