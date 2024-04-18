# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Ensure that only one node (re)starts, joins the cluster, or leaves the cluster at a time."""
import json
import logging
import os
import typing

import ops
from charms.opensearch.v0.helper_cluster import ClusterTopology
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


class _PeerRelationLock(ops.Object):
    """Fallback lock when all units of OpenSearch are offline."""

    _ENDPOINT_NAME = "node-lock-fallback"

    def __init__(self, charm: ops.CharmBase):
        super().__init__(charm, self._ENDPOINT_NAME)
        self._charm = charm
        self.framework.observe(
            self._charm.on[self._ENDPOINT_NAME].relation_changed, self._on_peer_relation_changed
        )

    @property
    def acquired(self) -> bool:
        """Attempt to acquire lock.

        Returns:
            Whether lock was acquired
        """
        if not self._relation:
            return False
        self._relation.data[self._charm.unit]["lock-requested"] = json.dumps(True)
        if self._charm.unit.is_leader():
            logger.debug("[Node lock] Requested peer lock as leader unit")
            # A separate relation-changed event won't get fired
            self._on_peer_relation_changed()
        if self._unit_with_lock != self._charm.unit.name:
            logger.debug(
                f"[Node lock] Not acquired. Unit with peer databag lock: {self._unit_with_lock}"
            )
            return False
        if (
            self._charm.unit.is_leader()
            and self._relation.data[self._charm.app]["leader-acquired-lock-after-juju-event-id"]
            == os.environ["JUJU_CONTEXT_ID"]
        ):
            # `unit-with-lock` was set in this Juju event
            # If the charm code raises an uncaught exception later in the Juju event,
            # `unit-with-lock` will be reverted to its previous value—which could allow another
            # unit to get the lock.
            # Therefore, we cannot use the lock now. We must wait until the next Juju event,
            # when `unit-with-lock` has been committed (i.e. won't be reverted), to use the
            # lock.
            if self._charm.app.planned_units() <= 1:
                # No other unit will get peer relation changed
                # Therefore, no other unit will be able to trigger peer relation changed on this
                # unit. We must use the lock now and accept that `unit-with-lock` could be reverted
                # if the charm code raises an uncaught exception later in the Juju event.
                logger.debug(
                    "[Node lock] Single unit deployment. Not waiting until next Juju event to use peer databag lock for leader unit"
                )
            else:
                logger.debug(
                    "[Node lock] Not acquired. Waiting until next Juju event to use peer databag lock for leader unit"
                )
                return False
        logger.debug("[Node lock] Acquired via peer databag")
        return True

    def release(self):
        """Release lock for this unit."""
        if not self._relation:
            return
        self._relation.data[self._charm.unit].pop("lock-requested", None)
        if self._charm.unit.is_leader():
            logger.debug("[Node lock] Released peer lock as leader unit")
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
    def _unit_with_lock(self) -> str | None:
        if self._relation:
            return self._relation.data[self._charm.app].get("unit-with-lock")

    @_unit_with_lock.setter
    def _unit_with_lock(self, value: str):
        assert self._relation
        assert self._unit_with_lock != value
        if value == self._charm.unit.name:
            logger.debug("[Node lock] (leader) granted peer lock to own unit")
            # Prevent leader unit from using lock in the same Juju event that it was granted
            # If the charm code raises an uncaught exception later in the Juju event,
            # `unit-with-lock` will be reverted to its previous value—which could allow another
            # unit to get the lock.
            # Therefore, we cannot use the lock in this Juju event. We must wait until the next
            # Juju event, when `unit-with-lock` has been committed (i.e. won't be reverted), to use
            # the lock.
            # `JUJU_CONTEXT_ID` is unique for each Juju event
            # (https://matrix.to/#/!xdClnUGkurzjxqiQcN:ubuntu.com/$yEGjGlDaIPBtCi8uB3fH6ZaXUjN7GF-Y2s9YwvtPM-o?via=ubuntu.com&via=matrix.org&via=cutefunny.art)
            self._relation.data[self._charm.app][
                "leader-acquired-lock-after-juju-event-id"
            ] = os.environ["JUJU_CONTEXT_ID"]
        self._relation.data[self._charm.app]["unit-with-lock"] = value

    @_unit_with_lock.deleter
    def _unit_with_lock(self):
        assert self._relation
        self._relation.data[self._charm.app].pop("unit-with-lock", None)
        self._relation.data[self._charm.app].pop("leader-acquired-lock-after-juju-event-id", None)

    @property
    def _relation(self):
        # Use property instead of `self._relation =` in `__init__()` because of ops Harness unit
        # tests
        return self._charm.model.get_relation(self._ENDPOINT_NAME)

    def _on_peer_relation_changed(self, _=None):
        """Grant & release lock."""
        assert self._relation
        if not self._charm.unit.is_leader():
            if self._relation.data[self._charm.app].get(
                "leader-acquired-lock-after-juju-event-id"
            ):
                # Trigger peer relation changed event on leader unit
                # Without this, the leader unit might not receive another event (to use the lock it
                # holds) until the next update status event
                # Use `JUJU_CONTEXT_ID` only to ensure that the value changes
                # (Value should never be read)
                # (If we set the same value that is currently in the databag, a peer relation
                # changed event will not be triggered)
                self._relation.data[self._charm.unit]["-trigger"] = os.environ["JUJU_CONTEXT_ID"]
            return
        if self._unit_with_lock and self._unit_requested_lock(
            self._charm.model.get_unit(self._unit_with_lock)
        ):
            # Lock still in use, do not release
            logger.debug("[Node lock] (leader) lock still in use")
            return
        # TODO: adjust which unit gets priority on lock after leader?
        # During initial startup, leader unit must start first
        # Give priority to leader unit
        for unit in (self._charm.unit, *self._relation.units):
            if self._unit_requested_lock(unit):
                self._unit_with_lock = unit.name
                logger.debug(f"[Node lock] (leader) granted peer lock to {unit.name=}")
                break
        else:
            logger.debug("[Node lock] (leader) cleared peer lock")
            del self._unit_with_lock


class OpenSearchNodeLock(ops.Object):
    """Ensure that only one node (re)starts, joins the cluster, or leaves the cluster at a time.

    Uses OpenSearch document for lock. Falls back to peer databag if no units online
    """

    OPENSEARCH_INDEX = ".charm_node_lock"

    def __init__(self, charm: "opensearch_base_charm.OpenSearchBaseCharm"):
        super().__init__(charm, "opensearch-node-lock")
        self._charm = charm
        self._opensearch = charm.opensearch
        self._peer = _PeerRelationLock(self._charm)

    def _unit_with_lock(self, host) -> str | None:
        """Unit that has acquired OpenSearch lock."""
        try:
            document_data = self._opensearch.request(
                "GET",
                endpoint=f"/{self.OPENSEARCH_INDEX}/_source/0",
                host=host,
                alt_hosts=self._charm.alt_hosts,
                retries=3,
            )
        except OpenSearchHttpError as e:
            if e.response_code == 404:
                # No unit has lock
                return
            raise
        return document_data["unit-name"]

    @property
    def acquired(self) -> bool:  # noqa: C901
        """Attempt to acquire lock.

        Returns:
            Whether lock was acquired
        """
        if self._opensearch.is_node_up():
            host = self._charm.unit_ip
        else:
            host = None
        alt_hosts = [host for host in self._charm.alt_hosts if self._opensearch.is_node_up(host)]
        if host or alt_hosts:
            logger.debug("[Node lock] 1+ opensearch nodes online")
            try:
                online_nodes = len(
                    ClusterTopology.nodes(
                        self._opensearch, use_localhost=host is not None, hosts=alt_hosts
                    )
                )
            except OpenSearchHttpError:
                logger.exception("Error getting OpenSearch nodes")
                return False
            logger.debug(f"[Node lock] Opensearch {online_nodes=}")
            assert online_nodes > 0
            if online_nodes >= 2:
                logger.debug("[Node lock] Attempting to acquire opensearch lock")
                # Acquire opensearch lock
                # Create index if it doesn't exist
                try:
                    self._opensearch.request(
                        "PUT",
                        endpoint=f"/{self.OPENSEARCH_INDEX}",
                        host=host,
                        alt_hosts=alt_hosts,
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
                        logger.exception("Error creating OpenSearch lock index")
                        return False
                # Attempt to create document id 0
                try:
                    self._opensearch.request(
                        "PUT",
                        endpoint=f"/{self.OPENSEARCH_INDEX}/_create/0?refresh=true",
                        host=host,
                        alt_hosts=alt_hosts,
                        retries=3,
                        payload={"unit-name": self._charm.unit.name},
                    )
                except OpenSearchHttpError as e:
                    if e.response_code == 409 and "document already exists" in e.response_body.get(
                        "error", {}
                    ).get("reason", ""):
                        # Document already created
                        pass
                    else:
                        logger.exception("Error creating OpenSearch lock document")
                        return False
            unit = self._unit_with_lock(host)
            if unit == self._charm.unit.name:
                # Lock acquired
                # Release peer databag lock, if any
                logger.debug("[Node lock] Acquired via opensearch")
                self._peer.release()
                logger.debug("[Node lock] Released redundant peer lock (if held)")
                return True
            if unit or online_nodes >= 2:
                # Another unit has lock
                # (Or document deleted after request to create document & before request in
                # `self._unit_with_lock()`)
                logger.debug(f"[Node lock] Not acquired. Unit with opensearch lock: {unit}")
                return False
            # If online_nodes == 1, we should acquire the lock via the peer databag.
            # If we acquired the lock via OpenSearch and this unit was stopping, we would be unable
            # to release the OpenSearch lock. For example, when scaling to 0.
            # Then, when 1+ OpenSearch nodes are online, a unit that no longer exists could hold
            # the lock.
            # Note: if online_nodes > 1, this situation is still possible (e.g. if this unit was
            # stopping and another unit went offline simultaneously)—but it's an edge case we don't
            # support (to reduce complexity & improve robustness in other cases).
            # If online_nodes > 1, we should re-attempt to acquire the OpenSearch lock.
            logger.debug("[Node lock] No unit has opensearch lock")
        logger.debug("[Node lock] Using peer databag for lock")
        # Request peer databag lock
        # If return value is True:
        # - Lock granted in previous Juju event
        # - OR, unit is leader & lock granted in this Juju event
        return self._peer.acquired

    def release(self):
        """Release lock.

        Limitation: if lock acquired via OpenSearch document and all units offline, OpenSearch
        document lock will not be released
        """
        logger.debug("[Node lock] Releasing lock")
        if self._opensearch.is_node_up():
            host = self._charm.unit_ip
        else:
            host = None
        alt_hosts = [host for host in self._charm.alt_hosts if self._opensearch.is_node_up(host)]
        if host or alt_hosts:
            logger.debug("[Node lock] Checking which unit has opensearch lock")
            # Check if this unit currently has lock
            if self._unit_with_lock(host) == self._charm.unit.name:
                logger.debug("[Node lock] Releasing opensearch lock")
                # Delete document id 0
                try:
                    self._opensearch.request(
                        "DELETE",
                        endpoint=f"/{self.OPENSEARCH_INDEX}/_doc/0?refresh=true",
                        host=host,
                        alt_hosts=alt_hosts,
                        retries=3,
                    )
                except OpenSearchHttpError as e:
                    if e.response_code != 404:
                        raise
                logger.debug("[Node lock] Released opensearch lock")
        self._peer.release()
        logger.debug("[Node lock] Released peer lock (if held)")
        logger.debug("[Node lock] Released lock")
