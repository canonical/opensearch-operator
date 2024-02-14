# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Class for Setting configuration in opensearch config files."""
import logging

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchHttpError,
    OpenSearchOpsLockAlreadyAcquiredError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.rolling_ops.v0.retriable_rolling_ops import WorkloadLockManager
from tenacity import retry, stop_after_attempt, wait_fixed

# The unique Charmhub library identifier, never change it
LIBID = "0924c6d81c604a15873ad43498cd6895"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2

logger = logging.getLogger(__name__)


class OpenSearchOpsLock(WorkloadLockManager):
    """This class covers the configuration changes depending on certain actions."""

    LOCK_INDEX = ".ops_lock"
    PEER_DATA_LOCK_FLAG = "ops_removing_unit"

    def __init__(self, charm):
        self._charm = charm
        self._opensearch = charm.opensearch

    def acquire_lock(self):
        """Acquire the lock."""
        self.acquire()

    def release_lock(self):
        """Release the lock."""
        self.release()

    def is_departing(self) -> bool:
        """Checks if the lock is held."""
        try:
            status_code = self._opensearch.request(
                "GET",
                endpoint=f"/{OpenSearchOpsLock.LOCK_INDEX}",
                host=self._charm.unit_ip if self._opensearch.is_node_up() else None,
                alt_hosts=self._charm.alt_hosts,
                retries=3,
                resp_status_code=True,
            )
            if status_code < 300:
                return True
        except OpenSearchHttpError as e:
            logger.warning(f"Error checking for ops_lock: {e}")
            pass
        return False

    def can_node_be_safe_stopped(self) -> bool:
        """Check if the node can be safely stopped."""
        # TODO: use PR#175 logic to check if the node can be safely stopped
        # based on the existing shards and replicas
        return True

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
