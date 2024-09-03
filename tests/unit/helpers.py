# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import responses
from ops.model import Model, Unit

NODE_ID = "yTLtw5wNQlCsHUcrKaU5Kw"


def mock_response_root(unit_name: str, host: str):
    """Add API mock for the API root ('/') query.

    Keep in mind to add @responses.activate decorator to the test function using this call!
    """
    expected_response_root = {
        "name": unit_name.replace("/", "-"),
        "cluster_name": "opensearch-nfp7",
        "cluster_uuid": "TYji6UEuSw2tnIL-z8xEOg",
        "version": {
            "distribution": "opensearch",
            "number": "2.14.0",
            "build_type": "tar",
            "build_hash": "30dd870855093c9dca23fc6f8cfd5c0d7c83127d",
            "build_date": "2024-08-05T16:00:25.471849593Z",
            "build_snapshot": False,
            "lucene_version": "9.10.0",
            "minimum_wire_compatibility_version": "7.10.0",
            "minimum_index_compatibility_version": "7.0.0",
        },
        "tagline": "The OpenSearch Project: https://opensearch.org/",
    }

    responses.add(
        method="GET",
        url=f"https://{host}:9200/",
        json=expected_response_root,
        status=200,
    )


def mock_response_nodes(unit_name: str, host: str, node_id: str = NODE_ID):
    """Add API mock for the API root ('/') query.

    Keep in mind to add @responses.activate decorator to the test function using this call!
    """
    expected_response_nodes = {
        "_nodes": {"total": 1, "successful": 1, "failed": 0},
        "cluster_name": "opensearch-nfp7",
        "nodes": {
            node_id: {
                "name": unit_name.replace("/", "-"),
                "transport_address": f"{host}:9300",
                "host": host,
                "ip": host,
                "version": "2.14.0",
                "build_type": "tar",
                "build_hash": "30dd870855093c9dca23fc6f8cfd5c0d7c83127d",
                "total_indexing_buffer": 107374182,
                "roles": ["cluster_manager", "coordinating_only", "data", "ingest", "ml"],
                "attributes": {
                    "shard_indexing_pressure_enabled": "true",
                    "app_id": "617e5f02-5be5-4e25-85f0-276b2347a5ad/opensearch",
                },
            },
        },
    }

    responses.add(
        method="GET", url=f"https://{host}:9200/_nodes", json=expected_response_nodes, status=200
    )


def get_relation_unit(model: Model, relation_name: str, unit_name: str) -> Unit | None:
    """Get the Unit object from the relation that matches unit_name."""
    relation = model.get_relation(relation_name)
    if not relation.units:
        return

    for unit in relation.units:
        if unit.name == unit_name:
            return unit
