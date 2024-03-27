# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Ensure that only one node (re)starts, joins the cluster, or leaves the cluster at a time."""
import enum
import json
import logging
import typing

import ops
from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchHttpError,
    OpenSearchOpsLockAlreadyAcquiredError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from tenacity import retry, stop_after_attempt, wait_fixed

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


class OpenSearchOpsLock:
    """This class covers the configuration changes depending on certain actions."""

    LOCK_INDEX = ".ops_lock"
    PEER_DATA_LOCK_FLAG = "ops_removing_unit"

    def __init__(self, charm):
        self._charm = charm
        self._opensearch = charm.opensearch

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(0.5), reraise=True)
    def acquire(self):
        """Method for Acquiring the "ops" lock."""
        # no lock acquisition needed if only 1 unit remaining
        if len(self._charm.model.get_relation(PeerRelationName).units) == 1:
            return

        # we check first on the peer data bag if the lock is already acquired
        if self._is_lock_in_peer_data():
            raise OpenSearchOpsLockAlreadyAcquiredError("Another unit is being removed.")

        host = self._charm.unit_ip if self._opensearch.is_node_up() else None

        # we can use opensearch to lock
        if host is not None or self._charm.alt_hosts:
            # Create index
            try:
                # attempt lock acquisition through index creation, should crash if index
                # already created, meaning another unit is holding the lock
                self._opensearch.request(
                    "PUT",
                    endpoint=f"/{OpenSearchOpsLock.LOCK_INDEX}",
                    host=host,
                    alt_hosts=self._charm.alt_hosts,
                    retries=3,
                )
                self._charm.peers_data.put(Scope.UNIT, OpenSearchOpsLock.PEER_DATA_LOCK_FLAG, True)
                return
            except OpenSearchHttpError as e:
                if e.response_code != 400:
                    raise
                raise OpenSearchOpsLockAlreadyAcquiredError("Another unit is being removed.")

        # we could not use opensearch for locking, we use the peer rel data bag
        self._charm.peers_data.put(Scope.UNIT, OpenSearchOpsLock.PEER_DATA_LOCK_FLAG, True)

    def release(self):
        """Method for Releasing the "ops" lock."""
        host = self._charm.unit_ip if self._opensearch.is_node_up() else None

        # can use opensearch to remove lock
        if host is not None or self._charm.alt_hosts:
            try:
                self._opensearch.request(
                    "DELETE",
                    endpoint=f"/{OpenSearchOpsLock.LOCK_INDEX}",
                    host=host,
                    alt_hosts=self._charm.alt_hosts,
                    retries=3,
                )
            except OpenSearchHttpError as e:
                # ignore 404, it means the index is not found and this just means that
                # the cleanup happened before but event got deferred because of another error
                if e.response_code != 404:
                    raise

        self._charm.peers_data.delete(Scope.UNIT, OpenSearchOpsLock.PEER_DATA_LOCK_FLAG)

    def _is_lock_in_peer_data(self) -> bool:
        """Method checking if lock acquired from the peer rel data."""
        rel = self._charm.model.get_relation(PeerRelationName)
        for unit in rel.units:
            if rel.data[unit].get(OpenSearchOpsLock.PEER_DATA_LOCK_FLAG) == "True":
                return True

        return False


class _PeerLockState(enum.Enum):
    ACQUIRED_BY_THIS_UNIT = enum.auto()
    ACQUIRED_BY_ANOTHER_UNIT = enum.auto()
    NOT_ACQUIRED = enum.auto()


class _PeerRelationEndpoint(ops.Object):
    _NAME = "foo"  # TODO

    def __init__(self, charm: ops.CharmBase):
        super().__init__(charm, self._NAME)
        self._charm = charm
        self._relation = self._charm.model.get_relation(self._NAME)
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
        """Request lock for this unit"""
        self._relation.data[self._charm.unit]["lock-requested"] = json.dumps(True)
        if self._charm.unit.is_leader():
            # A separate relation-changed event won't get fired
            self._on_peer_relation_changed()

    def release_lock(self):
        """Release lock for this unit"""
        self._relation.data[self._charm.unit].pop("lock-requested", None)
        if self._charm.unit.is_leader():
            # A separate relation-changed event won't get fired
            self._on_peer_relation_changed()

    def _unit_requested_lock(self, unit: ops.Unit):
        """Whether unit requested lock"""
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
        self._relation.data[self._charm.app]["unit-with-lock"] = value

    @_unit_with_lock.deleter
    def _unit_with_lock(self):
        self._relation.data[self._charm.app].pop("unit-with-lock", None)

    def _on_peer_relation_changed(self, _=None):
        """Grant & release lock"""
        if not self._charm.unit.is_leader():
            return
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

    _OPENSEARCH_INDEX = ".ops_lock"  # TODO: name
    # TODO: retries in requests

    def __init__(self, charm: "opensearch_base_charm.OpenSearchBaseCharm"):
        super().__init__(charm, "opensearch-node-lock")  # TODO: key
        self._charm = charm
        self._opensearch = charm.opensearch
        self._peer = _PeerRelationEndpoint(self._charm)

    def _lock_acquired(self, host):
        """Whether this unit has already acquired OpenSearch lock"""
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
    def acquired(self) -> bool:
        """Attempt to acquire lock

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
            # TODO: use retry from original implementation?
            # Create index if it doesn't exist
            try:
                self._opensearch.request(
                    "PUT",
                    endpoint=f"/{self._OPENSEARCH_INDEX}",
                    host=host,
                    alt_hosts=self._charm.alt_hosts,
                    retries=3,
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
                    endpoint=f"/{self._OPENSEARCH_INDEX}/_create/0",
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
        """Release lock"""
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
                        endpoint=f"/{self._OPENSEARCH_INDEX}/_doc/0",
                        host=host,
                        alt_hosts=self._charm.alt_hosts,
                        retries=3,
                    )
                except OpenSearchHttpError as e:
                    if e.response_code != 404:
                        raise
        self._peer.release_lock()
