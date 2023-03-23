#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import logging
from multiprocessing import Process, Queue
from types import SimpleNamespace

from opensearchpy import OpenSearch, TransportError
from opensearchpy.helpers import BulkIndexError, bulk
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import (
    get_admin_secrets,
    get_application_unit_ids,
    get_application_unit_ips,
    opensearch_client,
)

logging.getLogger("opensearch").setLevel(logging.ERROR)
logging.getLogger("opensearchpy.helpers").setLevel(logging.ERROR)


class ContinuousWrites:
    """Utility class for managing continuous writes."""

    INDEX_NAME = "series_index"
    CERT_PATH = "/tmp/ca_chain.cert"

    def __init__(self, ops_test: OpsTest):
        self._ops_test = ops_test
        self._is_stopped = True
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

    async def stop(self) -> int:
        """Stop the continuous writes process and return max inserted ID."""
        if not self._is_stopped:
            self._stop_process()

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
            return int(resp["aggregations"]["max_id"]["value"])
        finally:
            client.close()

    def _create_process(self):
        self._is_stopped = False
        self._queue = Queue()
        self._process = Process(
            target=ContinuousWrites._run_async,
            name="continuous_writes",
            args=(self._queue, 1, True),
        )

    def _stop_process(self):
        self._process.terminate()
        self._queue.close()
        self._is_stopped = True

    async def _secrets(self) -> str:
        """Fetch secrets and return the password."""
        secrets = await get_admin_secrets(
            self._ops_test, get_application_unit_ids(self._ops_test)[0]
        )
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
    async def _run(data_queue: Queue, starting_number: int, is_bulk: bool) -> None:
        write_value = starting_number

        data = data_queue.get(True)
        while True:
            if not data_queue.empty():
                data = data_queue.get(False)

            client = opensearch_client(
                data.hosts, "admin", data.password, ContinuousWrites.CERT_PATH
            )
            try:
                if is_bulk:
                    ContinuousWrites._bulk(client, write_value)
                else:
                    ContinuousWrites._index(client, write_value)
            except (BulkIndexError, TransportError):
                continue
            finally:
                client.close()

            write_value += 1

    @staticmethod
    def _bulk(client: OpenSearch, write_value: int) -> None:
        """Bulk Index group of docs."""
        data = []
        for i in range(100):
            val = write_value + i
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

        bulk(client, actions=data)

    @staticmethod
    def _index(client: OpenSearch, write_value: int) -> None:
        """Index single document."""
        client.index(
            index=ContinuousWrites.INDEX_NAME,
            id=write_value,
            body={"id": write_value, "title": f"title_{write_value}"},
        )

    @staticmethod
    def _run_async(data_queue: Queue, starting_number: int, is_bulk: bool):
        """Run async code."""
        asyncio.run(ContinuousWrites._run(data_queue, starting_number, is_bulk))
