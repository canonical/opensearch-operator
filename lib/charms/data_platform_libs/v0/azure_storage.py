#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from collections import namedtuple
from typing import Dict, List, Optional

from charms.data_platform_libs.v0.data_interfaces import (
    EventHandlers,
    ProviderData,
    RequirerData,
    RequirerEventHandlers,
)
from ops import Model
from ops.charm import (
    CharmBase,
    CharmEvents,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationEvent,
    RelationJoinedEvent,
    SecretChangedEvent,
)
from ops.framework import EventSource, ObjectEvents
from ops.model import Relation

# The unique Charmhub library identifier, never change it
LIBID = "fca396f6254246c9bfa5650000000000"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


AZURE_STORAGE_REQUIRED_INFO = ["container", "storage-account", "secret-key", "connection-protocol"]


class ObjectStorageEvent(RelationEvent):
    pass


class ContainerEvent(ObjectStorageEvent):
    """Base class for Azure storage events."""

    @property
    def container(self) -> Optional[str]:
        """Returns the container name."""
        if not self.relation.app:
            return None

        return self.relation.data[self.relation.app].get("container", "")


class StorageConnectionInfoRequestedEvent(ContainerEvent):
    pass


class StorageConnectionInfoChangedEvent(ContainerEvent):
    pass


class StorageConnectionInfoGoneEvent(RelationEvent):
    pass


class AzureStorageProviderEvents(CharmEvents):
    """Events for the AzureStorageProvider side implementation."""

    storage_connection_info_requested = EventSource(StorageConnectionInfoRequestedEvent)


class AzureStorageRequirerEvents(CharmEvents):
    """Events for the AzureStorageRequirer side implementation."""

    storage_connection_info_changed = EventSource(StorageConnectionInfoChangedEvent)
    storage_connection_info_gone = EventSource(StorageConnectionInfoGoneEvent)


class AzureStorageRequirerData(RequirerData):
    SECRET_FIELDS = ["secret-key"]

    def __init__(self, model, relation_name: str, container: Optional[str] = None):
        super().__init__(
            model,
            relation_name,
        )
        self.container = container


class AzureStorageRequirerEventHandlers(RequirerEventHandlers):
    """Event handlers for for requirer side of Azure Storage relation."""

    on = AzureStorageRequirerEvents()  # pyright: ignore[reportAssignmentType]

    def __init__(self, charm: CharmBase, relation_data: AzureStorageRequirerData):
        super().__init__(charm, relation_data)

        self.relation_name = relation_data.relation_name
        self.charm = charm
        self.local_app = self.charm.model.app
        self.local_unit = self.charm.unit

        self.framework.observe(
            self.charm.on[self.relation_name].relation_joined, self._on_relation_joined_event
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_relation_changed_event
        )

        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken,
            self._on_relation_broken_event,
        )

    def _on_relation_joined_event(self, event: RelationJoinedEvent) -> None:
        """Event emitted when the Azure Storage relation is joined."""
        logger.info(f"Azure storage relation ({event.relation.name}) joined...")
        if self.container is None:
            self.container = f"relation-{event.relation.id}"
        event_data = {"container": self.container}
        self.relation_data.update_relation_data(event.relation.id, event_data)

    def get_azure_storage_connection_info(self) -> Dict[str, str]:
        """Return the azure storage connection info as a dictionary."""
        for relation in self.relations:
            if relation and relation.app:
                info = self.relation_data.fetch_relation_data([relation.id])[relation.id]
                if not all([param in info for param in AZURE_STORAGE_REQUIRED_INFO]):
                    continue
                return info
        return {}

    def _on_relation_changed_event(self, event: RelationChangedEvent) -> None:
        """Notify the charm about the presence of Azure Storage credentials."""
        logger.info(f"Azure storage relation ({event.relation.name}) changed...")

        diff = self._diff(event)
        if any(newval for newval in diff.added if self.relation_data._is_secret_field(newval)):
            self.relation_data._register_secrets_to_relation(event.relation, diff.added)

        # check if the mandatory options are in the relation data
        contains_required_options = True
        credentials = self.get_azure_storage_connection_info()
        missing_options = []
        for configuration_option in AZURE_STORAGE_REQUIRED_INFO:
            if configuration_option not in credentials:
                contains_required_options = False
                missing_options.append(configuration_option)

        # emit credential change event only if all mandatory fields are present
        if contains_required_options:
            getattr(self.on, "storage_connection_info_changed").emit(
                event.relation, app=event.app, unit=event.unit
            )
        else:
            logger.warning(
                f"Some mandatory fields: {missing_options} are not present, do not emit credential change event!"
            )

    def _on_secret_changed_event(self, event: SecretChangedEvent):
        """Event handler for handling a new value of a secret."""
        if not event.secret.label:
            return

        relation = self.relation_data._relation_from_secret_label(event.secret.label)
        if not relation:
            logging.info(
                f"Received secret {event.secret.label} but couldn't parse, seems irrelevant."
            )
            return

        if event.secret.label != self.relation_data._generate_secret_label(
            relation.name,
            relation.id,
            "extra",
        ):
            logging.info("Secret is not relevant for us.")
            return

        if relation.app == self.charm.app:
            logging.info("Secret changed event ignored for Secret Owner")

        remote_unit = None
        for unit in relation.units:
            if unit.app != self.charm.app:
                remote_unit = unit

        # check if the mandatory options are in the relation data
        contains_required_options = True
        credentials = self.get_azure_storage_connection_info()
        missing_options = []
        for configuration_option in AZURE_STORAGE_REQUIRED_INFO:
            if configuration_option not in credentials:
                contains_required_options = False
                missing_options.append(configuration_option)

        # emit credential change event only if all mandatory fields are present
        if contains_required_options:
            getattr(self.on, "storage_connection_info_changed").emit(
                relation, app=relation.app, unit=remote_unit
            )
        else:
            logger.warning(
                f"Some mandatory fields: {missing_options} are not present, do not emit credential change event!"
            )

    def _on_relation_broken_event(self, event: RelationBrokenEvent) -> None:
        """Event handler for handling relation_broken event."""
        logger.info("Azure Storage relation broken...")
        getattr(self.on, "storage_connection_info_gone").emit(
            event.relation, app=event.app, unit=event.unit
        )

    @property
    def relations(self) -> List[Relation]:
        """The list of Relation instances associated with this relation_name."""
        return list(self.charm.model.relations[self.relation_name])


class AzureStorageRequires(AzureStorageRequirerData, AzureStorageRequirerEventHandlers):
    """The requirer side of Azure Storage relation."""

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
        container: Optional[str] = None,
    ):
        AzureStorageRequirerData.__init__(self, charm.model, relation_name, container)
        AzureStorageRequirerEventHandlers.__init__(self, charm, self)


class AzureStorageProviderData(ProviderData):
    """The Data abstraction of the provider side of Azure storage relation."""

    RESOURCE_FIELD = "container"

    def __init__(self, model: Model, relation_name: str) -> None:
        super().__init__(model, relation_name)


class AzureStorageProviderEventHandlers(EventHandlers):
    """The event handlers related to provider side of Azure Storage relation."""

    on = AzureStorageProviderEvents()

    def __init__(
        self, charm: CharmBase, relation_data: AzureStorageProviderData, unique_key: str = ""
    ):
        super().__init__(charm, relation_data, unique_key)
        self.relation_data = relation_data

    def _on_relation_changed_event(self, event: RelationChangedEvent):
        if not self.charm.unit.is_leader():
            return
        diff = self._diff(event)
        if "container" in diff.added:
            self.on.storage_connection_info_requested.emit(
                event.relation, app=event.app, unit=event.unit
            )

    def _on_secret_changed_event(self, event: SecretChangedEvent) -> None:
        """Event emitted when the secret has changed."""
        pass


class AzureStorageProvides(AzureStorageProviderData, AzureStorageProviderEventHandlers):
    """The provider side of the Azure Storage relation."""

    def __init__(self, charm: CharmBase, relation_name: str) -> None:
        AzureStorageProviderData.__init__(self, charm.model, relation_name)
        AzureStorageProviderEventHandlers.__init__(self, charm, self)
