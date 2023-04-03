#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import logging
import os
from multiprocessing import Event, Process, Queue
from types import SimpleNamespace

from opensearchpy import OpenSearch, TransportError
from opensearchpy.helpers import BulkIndexError, bulk
from pytest_operator.plugin import OpsTest
from tenacity import (
    RetryError,
    Retrying,
    retry,
    stop_after_attempt,
    stop_after_delay,
    wait_fixed,
    wait_random,
)

from tests.integration.helpers import (
    get_admin_secrets,
    get_application_unit_ips,
    opensearch_client,
)

logging.getLogger("opensearch").setLevel(logging.ERROR)
logging.getLogger("opensearchpy.helpers").setLevel(logging.ERROR)


class ContinuousWrites:
    """Utility class for managing continuous writes."""

    INDEX_NAME = "series_index"
    LAST_WRITTEN_VAL_PATH = "last_written_value"
    CERT_PATH = "/tmp/ca_chain.cert"

    def __init__(self, ops_test: OpsTest):
        self._ops_test = ops_test
        self._is_stopped = True
        self._event = None
        self._queue = None
        self._process = None

    async def start(self) -> None:
        """Run continuous writes in the background."""
        if not self._is_stopped:
            await self.clear()

        # create process
        self._create_process()

        # put data (hosts, password) in the process queue
        await self.update()

        # start writes
        self._process.start()

    async def update(self):
        """Update cluster related conf. Useful in cases such as scaling, pwd change etc."""
        password = await self._secrets()
        self._queue.put(
            SimpleNamespace(hosts=get_application_unit_ips(self._ops_test), password=password)
        )

    async def clear(self) -> None:
        """Stop writes and Delete the index."""
        if not self._is_stopped:
            await self.stop()

        client = await self._client()
        try:
            client.indices.delete(index=ContinuousWrites.INDEX_NAME)
        finally:
            client.close()

    async def count(self) -> int:
        """Count the number of documents in the index."""
        client = await self._client()
        try:
            # refresh the index so that all writes are visible on search
            client.indices.refresh(index=ContinuousWrites.INDEX_NAME)

            resp = client.count(index=ContinuousWrites.INDEX_NAME)
            return int(resp["count"])
        finally:
            client.close()

    async def stop(self) -> SimpleNamespace:
        """Stop the continuous writes process and return max inserted ID."""
        if not self._is_stopped:
            self._stop_process()

        result = SimpleNamespace()

        client = await self._client()
        try:
            # refresh the index so that all writes are visible on search
            client.indices.refresh(index=ContinuousWrites.INDEX_NAME)

            resp = client.search(
                index=ContinuousWrites.INDEX_NAME,
                body={
                    "size": 0,
                    "aggs": {"max_id": {"max": {"field": "id"}}},
                },
            )

            # max stored document id
            result.max_stored_id = int(resp["aggregations"]["max_id"]["value"])
        finally:
            client.close()

        # documents count
        result.count = await self.count()

        # last expected document id stored on disk
        try:
            for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(5)):
                with attempt:
                    with open(ContinuousWrites.LAST_WRITTEN_VAL_PATH, "r") as f:
                        result.last_expected_id = int(f.read().rstrip())
        except RetryError:
            result.last_expected_id = -1

        return result

    def _create_process(self):
        self._is_stopped = False
        self._event = Event()
        self._queue = Queue()
        self._process = Process(
            target=ContinuousWrites._run_async,
            name="continuous_writes",
            args=(self._event, self._queue, 0, True),
        )

    def _stop_process(self):
        self._event.set()
        self._process.join()
        self._queue.close()
        self._is_stopped = True

    async def _secrets(self) -> str:
        """Fetch secrets and return the password."""
        secrets = await get_admin_secrets(self._ops_test)
        with open(ContinuousWrites.CERT_PATH, "w") as chain:
            chain.write(secrets["ca-chain"])

        return secrets["password"]

    async def _client(self):
        """Build an opensearch client."""
        return opensearch_client(
            get_application_unit_ips(self._ops_test),
            "admin",
            await self._secrets(),
            ContinuousWrites.CERT_PATH,
        )

    @staticmethod
    async def _run(event: Event, data_queue: Queue, starting_number: int, is_bulk: bool) -> None:
        """Continuous writing."""

        def _client(_data) -> OpenSearch:
            return opensearch_client(
                _data.hosts, "admin", _data.password, ContinuousWrites.CERT_PATH
            )

        write_value = starting_number

        data = data_queue.get(True)
        client = _client(data)

        while True:
            if not data_queue.empty():  # currently evaluates to false as we don't make updates
                data = data_queue.get(False)
                client.close()
                client = _client(data)

            try:
                if is_bulk:
                    ContinuousWrites._bulk(client, write_value)
                else:
                    ContinuousWrites._index(client, write_value)
            except BulkIndexError:
                continue
            except TransportError:
                client.close()
                client = _client(data)
                continue
            finally:
                # process termination requested
                if event.is_set():
                    break

            write_value += 1

        # write last expected written value on disk
        with open(ContinuousWrites.LAST_WRITTEN_VAL_PATH, "w") as f:
            if is_bulk:
                write_value = (100 * write_value) + 99

            f.write(str(write_value))
            os.fsync(f)

        client.close()

    @staticmethod
    @retry(reraise=True, stop=stop_after_attempt(3), wait=wait_random(min=1, max=2))
    def _bulk(client: OpenSearch, write_value: int) -> None:
        """Bulk Index group of docs."""
        data = []
        for i in range(100):
            val = (100 * write_value) + i
            data.append(
                {
                    "_index": ContinuousWrites.INDEX_NAME,
                    "_id": val,
                    "_source": {
                        "id": val,
                        "title": f"title_{val}",
                    },
                }
            )

        success, errors = bulk(client, actions=data)
        if errors:
            raise BulkIndexError()

    @staticmethod
    @retry(reraise=True, stop=stop_after_attempt(3), wait=wait_random(min=1, max=2))
    def _index(client: OpenSearch, write_value: int) -> None:
        """Index single document."""
        client.index(
            index=ContinuousWrites.INDEX_NAME,
            id=write_value,
            body={"id": write_value, "title": f"title_{write_value}"},
        )

    @staticmethod
    def _run_async(event: Event, data_queue: Queue, starting_number: int, is_bulk: bool):
        """Run async code."""
        asyncio.run(ContinuousWrites._run(event, data_queue, starting_number, is_bulk))
