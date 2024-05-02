# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Base class for the OpenSearch Fixes of bugs introduced by upstream."""
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError

# The unique Charmhub library identifier, never change it
LIBID = "3bdf0a053a53493abefe8265dac85419"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class OpenSearchFixes:
    """This class implements various fixes of bugs introduced in OpenSearch upstream."""

    def __init__(self, charm):
        self._charm = charm

    def apply_on_start(self):
        """Fixes to apply on start."""
        self._reconfigure_replicas_of_builtin_indices()

    def _reconfigure_replicas_of_builtin_indices(self):
        """This changes the replication factor of some core indices."""
        # Bug https://github.com/opensearch-project/OpenSearch/issues/8862
        # Introduced in: 2.9.0
        target_indices = [
            ".plugins-ml-config",
            ".opensearch-sap-log-types-config",
            ".opensearch-sap-pre-packaged-rules-config",
        ]
        for index in target_indices:
            try:
                self._charm.opensearch.request(
                    method="PUT",
                    endpoint=f"/{index}?wait_for_active_shards=all",
                    payload={"settings": {"index": {"auto_expand_replicas": "0-all"}}},
                )
            except OpenSearchHttpError as e:
                if e.response_code != 404:
                    raise
