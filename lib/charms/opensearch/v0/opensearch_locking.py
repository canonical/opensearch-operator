# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Ensure that only one node (re)starts, joins the cluster, or leaves the cluster at a time."""
import enum
import json
import logging
import typing

import ops
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError

if typing.TYPE_CHECKING:
    import charms.opensearch.v0.opensearch_base_charm as opensearch_base_charm

# The unique Charmhub library identifier, never change it
LIBID = "0924c6d81c604a15873ad43498cd6895"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class _PeerLockState(enum.Enum):
    ACQUIRED_BY_THIS_UNIT = enum.auto()
    ACQUIRED_BY_ANOTHER_UNIT = enum.auto()
    NOT_ACQUIRED = enum.auto()


class _PeerRelationEndpoint(ops.Object):
    _NAME = "node-lock-fallback"

    def __init__(self, charm: ops.CharmBase):
        super().__init__(charm, self._NAME)
        self._charm = charm
        self.framework.observe(
            self._charm.on[self._NAME].relation_changed, self._on_peer_relation_changed
        )

    @property
    def state(self):
        if self._unit_with_lock:
            if self._unit_with_lock == self._charm.unit.name:
                return _PeerLockState.ACQUIRED_BY_THIS_UNIT
            return _PeerLockState.ACQUIRED_BY_ANOTHER_UNIT
        return _PeerLockState.NOT_ACQUIRED

    def request_lock(self):
        """Request lock for this unit."""
        if not self._relation:
            return
        self._relation.data[self._charm.unit]["lock-requested"] = json.dumps(True)
        if self._charm.unit.is_leader():
            # A separate relation-changed event won't get fired
            self._on_peer_relation_changed()

    def release_lock(self):
        """Release lock for this unit."""
        if not self._relation:
            return
        self._relation.data[self._charm.unit].pop("lock-requested", None)
        if self._charm.unit.is_leader():
            # A separate relation-changed event won't get fired
            self._on_peer_relation_changed()

    def _unit_requested_lock(self, unit: ops.Unit):
        """Whether unit requested lock."""
        assert self._relation
        value = self._relation.data[unit].get("lock-requested")
        if not value:
            return False
        value = json.loads(value)
        if not isinstance(value, bool):
            raise ValueError
        return value

    @property
    def _unit_with_lock(self):
        if self._relation:
            return self._relation.data[self._charm.app].get("unit-with-lock")

    @_unit_with_lock.setter
    def _unit_with_lock(self, value: str):
        assert self._relation
        self._relation.data[self._charm.app]["unit-with-lock"] = value

    @_unit_with_lock.deleter
    def _unit_with_lock(self):
        assert self._relation
        self._relation.data[self._charm.app].pop("unit-with-lock", None)

    @property
    def _relation(self):
        # Use property instead of `self._relation =` in `__init__()` because of ops Harness unit
        # tests
        return self._charm.model.get_relation(self._NAME)

    def _on_peer_relation_changed(self, _=None):
        """Grant & release lock."""
        if not self._charm.unit.is_leader():
            return
        assert self._relation
        if self._unit_with_lock and self._unit_requested_lock(
            self._charm.model.get_unit(self._unit_with_lock)
        ):
            # Lock still in use, do not release
            return
        # TODO: adjust which unit gets priority on lock?
        for unit in (*self._relation.units, self._charm.unit):
            if self._unit_requested_lock(unit):
                self._unit_with_lock = unit.name
                break
        else:
            del self._unit_with_lock


class OpenSearchNodeLock(ops.Object):
    """Ensure that only one node (re)starts, joins the cluster, or leaves the cluster at a time.

    Uses OpenSearch document for lock. Falls back to peer databag if no units online
    """

    _OPENSEARCH_INDEX = ".charm_node_lock"

    def __init__(self, charm: "opensearch_base_charm.OpenSearchBaseCharm"):
        super().__init__(charm, "opensearch-node-lock")
        self._charm = charm
        self._opensearch = charm.opensearch
        self._peer = _PeerRelationEndpoint(self._charm)

    def _lock_acquired(self, host):
        """Whether this unit has already acquired OpenSearch lock."""
        try:
            document_data = self._opensearch.request(
                "GET",
                endpoint=f"/{self._OPENSEARCH_INDEX}/_source/0",
                host=host,
                alt_hosts=self._charm.alt_hosts,
                retries=3,
            )
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                # No unit has lock
                return False
            raise
        return document_data["unit-name"] == self._charm.unit.name

    @property
    def acquired(self) -> bool:  # noqa: C901
        """Attempt to acquire lock.

        Returns:
            Whether lock was acquired
        """
        # In peer databag, check if lock acquired by another unit
        if self._peer.state is _PeerLockState.ACQUIRED_BY_ANOTHER_UNIT:
            return False

        if self._opensearch.is_node_up():
            host = self._charm.unit_ip
        else:
            host = None
        if host or self._charm.alt_hosts:
            # Acquire opensearch lock
            # Create index if it doesn't exist
            try:
                self._opensearch.request(
                    "PUT",
                    endpoint=f"/{self._OPENSEARCH_INDEX}",
                    host=host,
                    alt_hosts=self._charm.alt_hosts,
                    retries=3,
                    payload={"settings": {"index": {"auto_expand_replicas": "0-all"}}},
                )
            except OpenSearchHttpError as e:
                if (
                    e.response_code == 400
                    and e.response_body.get("error", {}).get("type")
                    == "resource_already_exists_exception"
                ):
                    # Index already created
                    pass
                else:
                    raise
            # Attempt to create document id 0
            try:
                self._opensearch.request(
                    "PUT",
                    endpoint=f"/{self._OPENSEARCH_INDEX}/_create/0?refresh=true",
                    host=host,
                    alt_hosts=self._charm.alt_hosts,
                    retries=3,
                    payload={"unit-name": self._charm.unit.name},
                )
            except OpenSearchHttpError as e:
                if e.response_code == 409 and "document already exists" in e.response_body.get(
                    "error", {}
                ).get("reason", ""):
                    # Document already created
                    if not self._lock_acquired(host):
                        # Another unit has lock
                        # (Or document deleted after last request & before request in
                        # `self._lock_acquired()`)
                        return False
                else:
                    raise
            # Lock acquired
            # Release peer databag lock, if any
            self._peer.release_lock()
            return True
        else:
            # Request peer databag lock
            self._peer.request_lock()
            # If expression is True:
            # - Lock granted in previous Juju event
            # - OR, unit is leader & lock granted in this Juju event
            return self._peer.state is _PeerLockState.ACQUIRED_BY_THIS_UNIT

    def release(self):
        """Release lock.

        Limitation: if lock acquired via OpenSearch document and all units offline, OpenSearch
        document lock will not be released
        """
        if self._opensearch.is_node_up():
            host = self._charm.unit_ip
        else:
            host = None
        if host or self._charm.alt_hosts:
            # Check if this unit currently has lock
            if self._lock_acquired(host):
                # Delete document id 0
                try:
                    self._opensearch.request(
                        "DELETE",
                        endpoint=f"/{self._OPENSEARCH_INDEX}/_doc/0?refresh=true",
                        host=host,
                        alt_hosts=self._charm.alt_hosts,
                        retries=3,
                    )
                except OpenSearchHttpError as e:
                    if e.response_code != 404:
                        raise
        self._peer.release_lock()
