#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import multiprocessing

from integration.helpers import client
from opensearchpy import OpenSearch, TransportError
from opensearchpy.helpers import BulkIndexError, streaming_bulk
from pytest_operator.plugin import OpsTest


class ContinuousWrites:
    """Utility class for managing continuous writes."""

    INDEX_NAME = "my_index"

    @staticmethod
    def start(ops_test: OpsTest, starting_number: int) -> None:
        # run continuous writes in the background.
        process = multiprocessing.Process(
            target=ContinuousWrites._start_writes,
            name="continuous_writes",
            args=(
                ops_test,
                starting_number,
                True,
            ),
        )
        process.start()

    @staticmethod
    async def stop(ops_test: OpsTest) -> int:
        """Stop the continuous writes process and return max id."""
        for process in multiprocessing.active_children():
            if process.name == "continuous_writes":
                process.terminate()

        opensearch_client = await client(ops_test)
        try:
            # refresh the index so that all writes are visible on search
            opensearch_client.indices.refresh(index=ContinuousWrites.INDEX_NAME)

            resp = opensearch_client.search(
                index=ContinuousWrites.INDEX_NAME,
                body={
                    "size": 0,
                    "aggs": {"max_id": {"max": {"field": "id"}}},
                },
            )
            return int(resp["aggregations"]["max_id"]["value"])
        finally:
            opensearch_client.close()

    @staticmethod
    async def clear(ops_test: OpsTest) -> None:
        """Stop writes and Delete the index."""
        await ContinuousWrites.stop(ops_test)

        opensearch_client = await client(ops_test)
        try:
            opensearch_client.indices.delete(index=ContinuousWrites.INDEX_NAME)
        finally:
            opensearch_client.close()

    @staticmethod
    async def count(ops_test: OpsTest) -> int:
        """Count the number of documents in the index."""
        opensearch_client = await client(ops_test)
        try:
            # refresh the index so that all writes are visible on search
            opensearch_client.indices.refresh(index=ContinuousWrites.INDEX_NAME)

            resp = opensearch_client.count(index=ContinuousWrites.INDEX_NAME)
            return int(resp["count"])
        finally:
            opensearch_client.close()

    @staticmethod
    async def _start_writes(ops_test: OpsTest, starting_number: int, is_bulk: bool = True) -> None:
        write_value = starting_number

        while True:
            opensearch_client = await client(ops_test)
            try:
                if is_bulk:
                    ContinuousWrites._bulk(opensearch_client, write_value)
                else:
                    ContinuousWrites._index(opensearch_client, write_value)
            except (BulkIndexError, TransportError):
                continue
            finally:
                opensearch_client.close()

        write_value += 1

    @staticmethod
    def _bulk(opensearch_client: OpenSearch, write_value: int) -> None:
        """Bulk Index group of docs."""
        data = []
        for i in range(100):
            val = write_value + i
            data.append(
                {
                    "_index": ContinuousWrites.INDEX_NAME,
                    "_id": val,
                    "_source": {
                        "title": f"title_{val}",
                        "val": val,
                    },
                }
            )

        streaming_bulk(opensearch_client, actions=data)

    @staticmethod
    def _index(opensearch_client: OpenSearch, write_value: int) -> None:
        """Index single document."""
        opensearch_client.index(
            index=ContinuousWrites.INDEX_NAME,
            id=write_value,
            body={"title": f"title_{write_value}", "val": write_value},
        )
