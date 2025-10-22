# Copyright 2025 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

r"""A library for communicating with the S3 credentials providers and consumers.

This library provides the relevant interface code implementing the communication
specification for fetching, retrieving, triggering, and responding to events related to
the S3 provider charm and its consumers.


### Provider charm

The provider is implemented in the `s3-integrator` charm which is meant to be deployed
alongside one or more consumer charms. The provider charm is serving the s3 credentials and
metadata needed to communicate and work with an S3 compatible backend.

Example:
```python

from s3_lib import (
    S3ProviderData,
    S3ProviderEventHandlers,
    StorageConnectionInfoRequestedEvent,
)

class ExampleProviderCharm(CharmBase):
    def __init__(self, *args) -> None:
        super().__init__(*args)

        self.s3_provider_data = S3ProviderData(self.charm.model, S3_RELATION_NAME)
        self.s3_provider = S3ProviderEventHandlers(self.charm, self.s3_provider_data)

        self.framework.observe(
            self.s3_provider.on.storage_connection_info_requested,
            self._on_s3_connection_info_requested,
        )

    def _on_s3_connection_info_requested(self, _: StorageConnectionInfoRequestedEvent) -> None:
        if not self.charm.unit.is_leader():
            return

        bucket_name = self.charm.config.get("bucket")
        if not bucket_name:
            self.logger.warning("Bucket is setup by the requirer application!")

        self.s3_provider_data.update({})


if __name__ == "__main__":
    main(ExampleProviderCharm)


### Requirer charm

The requirer charm is the charm requiring the S3 credentials.
An example of requirer charm is the following:

Example:
```python

from s3_lib import S3Requires, StorageConnectionInfoChangedEvent, StorageConnectionInfoGoneEvent

class ExampleRequirerCharm(CharmBase):

    def __init__(self, *args):
        super().__init__(*args)

         bucket_name = "test-bucket"
        # if bucket name is not provided the bucket name will be generated
        # e.g., ('relation-{relation.id}')

        self.s3_client = S3Requires(self, "s3-credentials", bucket_name)

        self.framework.observe(self.s3_client.on.s3_connection_info_changed, self._on_credential_changed)
        self.framework.observe(self.s3_client.on.s3_connection_info_gone, self._on_credential_gone)

    def _on_credential_changed(self, event: StorageConnectionInfoChangedEvent):

        # access single parameter credential
        secret_key = event.secret_key
        access_key = event.access_key

    def _on_credential_gone(self, event: StorageConnectionInfoGoneEvent):
        # credentials are removed
        pass

 if __name__ == "__main__":
    main(ExampleRequirerCharm)
```
"""

import logging
from typing import Dict, List, Optional  # using py38-style typing

from charms.data_platform_libs.v0.data_interfaces import (
    REQ_SECRET_FIELDS,
    EventHandlers,
    PrematureDataAccessError,
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
from ops.framework import EventSource
from ops.model import Relation

# The unique Charmhub library identifier, never change it
LIBID = "fca396f6254246c9bfa565b1f85ab528"

# Increment this major API version when introducing breaking changes
LIBAPI = 1

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 0


logger = logging.getLogger(__name__)


S3_REQUIRED_OPTIONS = ["access-key", "secret-key"]
S3_LIB_VERSION_FIELD = "lib-version"


class BucketEvent(RelationEvent):
    """Base class for bucket events."""

    @property
    def bucket(self) -> Optional[str]:
        """Returns the bucket was requested."""
        if not self.relation.app:
            return None

        return self.relation.data[self.relation.app].get("bucket", "")

    @property
    def path(self) -> Optional[str]:
        """Returns the path that was requested."""
        if not self.relation.app:
            return None

        return self.relation.data[self.relation.app].get("path", "")


class StorageConnectionInfoRequestedEvent(BucketEvent):
    """Event emitted when S3 credentials are requested on this relation."""


class StorageConnectionInfoChangedEvent(BucketEvent):
    """Event emitted when S3 credentials are changed for this relation."""


class StorageConnectionInfoGoneEvent(RelationEvent):
    """Event emitted when S3 credentials must be removed from this relation."""


class S3ProviderEvents(CharmEvents):
    """Events for the S3Provider side implementation."""

    storage_connection_info_requested = EventSource(StorageConnectionInfoRequestedEvent)


class S3RequirerEvents(CharmEvents):
    """Events for the S3Requirer side implementation."""

    s3_connection_info_changed = EventSource(StorageConnectionInfoChangedEvent)
    s3_connection_info_gone = EventSource(StorageConnectionInfoGoneEvent)


class S3RequirerData(RequirerData):
    """Requires-side data."""

    SECRET_FIELDS = ["access-key", "secret-key"]

    def __init__(self, model, relation_name: str, bucket: str, path: str) -> None:
        super().__init__(
            model,
            relation_name,
        )
        self._local_secret_fields: list[str] = []
        self.bucket = bucket
        self.path = path


class S3RequirerEventHandlers(RequirerEventHandlers):
    """Event handlers for for requirer side of S3 relation."""

    on = S3RequirerEvents()  # type: ignore

    def __init__(self, charm: CharmBase, relation_data: S3RequirerData):
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
        """Event emitted when the S3 relation is joined."""
        logger.debug(f"S3 relation ({event.relation.name}) joined...")
        event_data = {
            "bucket": self.relation_data.bucket,
            "path": self.relation_data.path,
            S3_LIB_VERSION_FIELD: f"{LIBAPI}.{LIBPATCH}",
        }
        self.relation_data.update_relation_data(event.relation.id, event_data)

    def get_s3_connection_info(self) -> Dict[str, str]:
        """Return the S3 connection info as a dictionary."""
        for relation in self.relations:
            if relation and relation.app:
                info = self.relation_data.fetch_relation_data([relation.id])[relation.id]
                if set(S3_REQUIRED_OPTIONS) - set(info):
                    continue
                info.pop(S3_LIB_VERSION_FIELD, None)
                return info
        return {}

    def _on_relation_changed_event(self, event: RelationChangedEvent) -> None:
        """Notify the charm about the presence of S3 credentials."""
        logger.debug(f"S3 relation ({event.relation.name}) changed...")

        diff = self._diff(event)
        if any(newval for newval in diff.added if self.relation_data._is_secret_field(newval)):
            self.relation_data._register_secrets_to_relation(event.relation, diff.added)

        provider_lib_version = float(
            self.relation_data.fetch_relation_field(event.relation.id, S3_LIB_VERSION_FIELD) or "0"
        )
        if provider_lib_version < 1 and not self.relation_data.fetch_my_relation_field(
            event.relation.id, "bucket"
        ):
            # The following line exists here due to compatibility for v1 requirer to work with v0 provider
            # The v0 provider will still wait for `bucket` to appear in the databag, and if it does not exist,
            # the provider will simply not write any data to the databag.
            self.relation_data.update_relation_data(
                event.relation.id, {"bucket": f"relation-{event.relation.id}"}
            )

        # check if the mandatory options are in the relation data
        contains_required_options = True
        credentials = self.get_s3_connection_info()
        missing_options = []
        for configuration_option in S3_REQUIRED_OPTIONS:
            if configuration_option not in credentials:
                contains_required_options = False
                missing_options.append(configuration_option)

        # emit credential change event only if all mandatory fields are present
        if contains_required_options:
            getattr(self.on, "s3_connection_info_changed").emit(
                event.relation, app=event.app, unit=event.unit
            )
        else:
            logger.warning(
                f"Some mandatory fields: {missing_options} are not present, do not emit credential change event!"
            )

    def _on_secret_changed_event(self, event: SecretChangedEvent) -> None:
        """Event handler for handling a new value of a secret."""
        if not event.secret.label:
            return

        relation = self.relation_data._relation_from_secret_label(event.secret.label)
        if not relation:
            logger.info(
                f"Received secret {event.secret.label} but couldn't parse, seems irrelevant."
            )
            return

        if event.secret.label != self.relation_data._generate_secret_label(
            relation.name,
            relation.id,
            "extra",
        ):
            logger.info("Secret is not relevant for us.")
            return

        if relation.app == self.charm.app:
            logger.info("Secret changed event ignored for Secret Owner")
            return

        remote_unit = None
        for unit in relation.units:
            if unit.app != self.charm.app:
                remote_unit = unit
                break
        else:
            return

        # check if the mandatory options are in the relation data
        contains_required_options = True
        credentials = self.get_s3_connection_info()
        missing_options = []
        for configuration_option in S3_REQUIRED_OPTIONS:
            if configuration_option not in credentials:
                contains_required_options = False
                missing_options.append(configuration_option)

        # emit credential change event only if all mandatory fields are present
        if contains_required_options:
            getattr(self.on, "s3_connection_info_changed").emit(
                relation, app=relation.app, unit=remote_unit
            )
        else:
            logger.warning(
                f"Some mandatory fields: {missing_options} are not present, do not emit credential change event!"
            )

    def _on_relation_broken_event(self, event: RelationBrokenEvent) -> None:
        """Event handler for handling relation_broken event."""
        logger.debug("S3 relation broken...")
        getattr(self.on, "s3_connection_info_gone").emit(
            event.relation, app=event.app, unit=event.unit
        )

    @property
    def relations(self) -> List[Relation]:
        """The list of Relation instances associated with this relation_name."""
        return list(self.charm.model.relations[self.relation_name])


class S3Requires(S3RequirerData, S3RequirerEventHandlers):
    """The requirer side of S3 relation."""

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str,
        bucket: str = "",
        path: str = "",
    ):
        S3RequirerData.__init__(self, charm.model, relation_name, bucket, path)
        S3RequirerEventHandlers.__init__(self, charm, self)


class S3ProviderData(ProviderData):
    """The Data abstraction of the provider side of S3 relation."""

    RESOURCE_FIELD = "bucket"

    def __init__(self, model: Model, relation_name: str) -> None:
        super().__init__(model, relation_name)

    def fetch_relation_data(
        self,
        relation_ids: list[int] | None = None,
        fields: list[str] | None = None,
        relation_name: str | None = None,
    ):
        """Override the behavior of `fetch_relation_data` to remove `bucket` field if request is from LIBAPI=0.

        This is required because LIBAPI=0 requirer automatically sets a bucket name as `relation-id-xxx` which used
        to be ignored by LIBAPI=1 provider when providing S3 credentials. The same behavior is expected from LIBAPI=1,
        if the request is from s3 lib with LIBAPI=0.
        """
        secret_fields = super().fetch_relation_data(
            relation_ids, [REQ_SECRET_FIELDS], relation_name
        )
        return_data = {}
        for relation_id, relation_data in (
            super()
            .fetch_relation_data(
                relation_ids=relation_ids, fields=fields, relation_name=relation_name
            )
            .items()
        ):
            return_data[relation_id] = relation_data
            if not secret_fields.get(relation_id, {}).get(REQ_SECRET_FIELDS):
                # This means the request is coming from S3 LIBAPI=0
                logger.info(
                    "The requirer is using s3 lib LIBAPI=0, thus discarding the 'bucket' parameter."
                )
                return_data[relation_id].pop("bucket", None)
        return return_data

    def _update_relation_data(self, relation: Relation, data: Dict[str, str]) -> None:
        """Override `update_relation_data` to bypass the parent's validation that raises PrematureDataAccessError."""
        relation_id = relation.id
        data_from_requirer = super().fetch_relation_data(
            [relation.id], [S3_LIB_VERSION_FIELD, self.RESOURCE_FIELD], relation.name
        )
        keys = set(data.keys())
        if (
            keys - {S3_LIB_VERSION_FIELD}
            and data_from_requirer.get(relation_id, {}).get(S3_LIB_VERSION_FIELD) is None
            and data_from_requirer.get(relation_id, {}).get(self.RESOURCE_FIELD) is None
        ):
            # The logic here is that the provider should not start writing S3 data to the databag
            # before the requirer has asked for it (during their relation-joined) with either:
            #           RESOURCE_FIELD: a field guaranteed to be there if LIBAPI=0
            #       OR  S3_LIB_VERSION_FIELD: a field guaranteed to be there if LIBAPI=1
            raise PrematureDataAccessError(
                "Premature access to relation data, update is forbidden before the connection is initialized."
            )
        super(ProviderData, self)._update_relation_data(relation, data)


class S3ProviderEventHandlers(EventHandlers):
    """The event handlers related to provider side of S3 relation."""

    on = S3ProviderEvents()  # type: ignore

    def __init__(self, charm: CharmBase, relation_data: S3ProviderData, unique_key: str = ""):
        super().__init__(charm, relation_data, unique_key)
        self.relation_data = relation_data

    def _on_relation_created_event(self, event: RelationJoinedEvent) -> None:
        """Event emitted when the S3 relation is created."""
        logger.debug(f"S3 relation ({event.relation.name}) created on provider side...")
        event_data = {
            S3_LIB_VERSION_FIELD: f"{LIBAPI}.{LIBPATCH}",
        }
        self.relation_data.update_relation_data(event.relation.id, event_data)

    def _on_relation_changed_event(self, event: RelationChangedEvent):
        if not self.charm.unit.is_leader():
            return
        self.on.storage_connection_info_requested.emit(
            event.relation, app=event.app, unit=event.unit
        )

    def _on_secret_changed_event(self, event: SecretChangedEvent) -> None:
        """Event emitted when the secret has changed.

        This method is called by the event handler on `secret-changed` event due to being registered in
        the parent class.If this method is overridden, `secret-changed` event need not be observed separately.
        """
        pass


class S3Provides(S3ProviderData, S3ProviderEventHandlers):
    """The provider side of the S3 relation."""

    def __init__(self, charm: CharmBase, relation_name: str) -> None:
        S3ProviderData.__init__(self, charm.model, relation_name)
        S3ProviderEventHandlers.__init__(self, charm, self)