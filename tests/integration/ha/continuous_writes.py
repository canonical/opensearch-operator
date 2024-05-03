#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import asyncio
import logging
import os
import time
from multiprocessing import Event, Process, Queue, log_to_stderr
from types import SimpleNamespace
from typing import Optional

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

from ..helpers import get_application_unit_ips, get_secrets, opensearch_client

logging.getLogger("opensearch").setLevel(logging.ERROR)
logging.getLogger("opensearchpy.helpers").setLevel(logging.ERROR)


class ContinuousWrites:
    """Utility class for managing continuous writes."""

    INDEX_NAME = "series_index"
    LAST_WRITTEN_VAL_PATH = "last_written_value"
    CERT_PATH = "/tmp/ca_chain.cert"

    def __init__(self, ops_test: OpsTest, app: str, initial_count: int = 0):
        self._ops_test = ops_test
        self._app = app
        self._is_stopped = True
        self._event = None
        self._queue = None
        self._process = None
        self._initial_count = initial_count

    @retry(
        wait=wait_fixed(wait=5) + wait_random(0, 5),
        stop=stop_after_attempt(5),
    )
    async def start(self, repl_on_all_nodes: bool = False, is_bulk: bool = True) -> None:
        """Run continuous writes in the background."""
        if not self._is_stopped:
            await self.clear()

        # create index if custom conf needed
        if repl_on_all_nodes:
            await self._create_fully_replicated_index()

        # create process
        self._create_process(is_bulk=is_bulk)

        # put data (hosts, password) in the process queue
        await self.update()

        # start writes
        self._process.start()

    async def update(self):
        """Update cluster related conf. Useful in cases such as scaling, pwd change etc."""
        password = await self._secrets()
        self._queue.put(
            SimpleNamespace(
                hosts=await get_application_unit_ips(self._ops_test, app=self._app),
                password=password,
            )
        )

    @retry(
        wait=wait_fixed(wait=5) + wait_random(0, 5),
        stop=stop_after_attempt(5),
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

    @retry(
        wait=wait_fixed(wait=5) + wait_random(0, 5),
        stop=stop_after_attempt(5),
    )
    async def count(self, unit_ip: Optional[str] = None, preference: Optional[str] = None) -> int:
        """Count the number of documents in the index."""
        client = await self._client(unit_ip)
        try:
            # refresh the index so that all writes are visible on search
            client.indices.refresh(index=ContinuousWrites.INDEX_NAME)

            resp = client.count(index=ContinuousWrites.INDEX_NAME, preference=preference)
            return int(resp["count"])
        finally:
            client.close()

    async def max_stored_id(self) -> int:
        """Query the max stored document id."""
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
            return int(resp["aggregations"]["max_id"]["value"])
        finally:
            client.close()

    async def _create_fully_replicated_index(self):
        """Create index with 1 p_shard and an r_shard on each node."""
        client = await self._client()
        try:
            # create index with a replica shard on every node
            client.indices.create(
                index=ContinuousWrites.INDEX_NAME,
                body={
                    "settings": {"index": {"number_of_shards": 2, "auto_expand_replicas": "1-all"}}
                },
                wait_for_active_shards="all",
            )
        finally:
            client.close()

    @retry(
        wait=wait_fixed(wait=5) + wait_random(0, 5),
        stop=stop_after_attempt(5),
    )
    async def stop(self) -> SimpleNamespace:
        """Stop the continuous writes process and return max inserted ID."""
        if not self._is_stopped:
            self._stop_process()

        result = SimpleNamespace()

        # max stored document id
        result.max_stored_id = await self.max_stored_id()

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

    def _create_process(self, is_bulk: bool = True):
        self._is_stopped = False
        self._event = Event()
        self._queue = Queue()
        self._process = Process(
            target=ContinuousWrites._run_async,
            name="continuous_writes",
            args=(self._event, self._queue, self._initial_count, is_bulk),
        )

    def _stop_process(self):
        if self._is_stopped or not self._process.is_alive():
            self._is_stopped = True
            return

        self._event.set()
        self._process.join()
        self._queue.close()
        self._process.terminate()
        self._is_stopped = True

    async def _secrets(self) -> str:
        """Fetch secrets and return the password."""
        secrets = await get_secrets(self._ops_test)
        with open(ContinuousWrites.CERT_PATH, "w") as chain:
            chain.write(secrets["ca-chain"])

        return secrets["password"]

    async def _client(self, unit_ip: Optional[str] = None):
        """Build an opensearch client."""
        hosts = await get_application_unit_ips(self._ops_test, app=self._app)
        if unit_ip:
            hosts = [unit_ip]

        return opensearch_client(
            hosts,
            "admin",
            await self._secrets(),
            ContinuousWrites.CERT_PATH,
        )

    @staticmethod
    async def _run(  # noqa: C901
        event: Event, data_queue: Queue, starting_number: int, is_bulk: bool
    ) -> None:
        """Continuous writing."""
        proc_logger = log_to_stderr()
        proc_logger.setLevel(logging.INFO)

        def _client(_data) -> OpenSearch:
            return opensearch_client(
                _data.hosts, "admin", _data.password, ContinuousWrites.CERT_PATH
            )

        write_value = starting_number

        proc_logger.info(
            f"Starting continuous writes from {write_value} with is_bulk={is_bulk}..."
        )

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

                # todo: remove when we get bigger runners (to reduce data transfer time)
                time.sleep(1)
            except BulkIndexError:
                proc_logger.info(f"Bulk failed for {write_value}")
                continue
            except (TransportError, ConnectionRefusedError):
                client.close()
                try:
                    client = _client(data)
                except (TransportError, ConnectionRefusedError):
                    pass

                proc_logger.info(f"Transport or Conn Refused error for {write_value}")
                continue
            finally:
                # process termination requested
                if event.is_set():
                    break

            write_value += 1

        # write last expected written value on disk
        with open(ContinuousWrites.LAST_WRITTEN_VAL_PATH, "w") as f:
            if is_bulk:
                write_value += 99

            f.write(str(write_value))
            os.fsync(f)

        client.close()

    @staticmethod
    @retry(reraise=True, stop=stop_after_attempt(3), wait=wait_random(min=1, max=2))
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
