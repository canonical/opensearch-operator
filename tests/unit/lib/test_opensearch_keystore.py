# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the opensearch keystore library."""
import unittest
from unittest.mock import MagicMock, call

from ops.testing import Harness

from charm import OpenSearchOperatorCharm

RETURN_LIST_KEYSTORE = """key1
key2
keystore.seed"""


class TestOpenSearchKeystore(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.charm = self.harness.charm
        self.keystore = self.charm.keystore_manager

    def test_keystore_add_keypair(self) -> None:
        """Add data to keystore."""
        self.charm.opensearch.request = MagicMock(return_value={"status": 200})
        self.charm.opensearch.run_bin = MagicMock(return_value="")
        self.keystore.put_entries({"key1": "secret1"})
        self.charm.opensearch.run_bin.assert_has_calls(
            [call("keystore", "add key1 --force", stdin="secret1")]
        )

    def test_keystore_delete_keypair(self) -> None:
        """Delete data to keystore."""
        self.charm.opensearch.request = MagicMock(return_value={"status": 200})
        self.charm.opensearch.run_bin = MagicMock(return_value="")
        self.keystore.remove_entries(["key1"])
        self.charm.opensearch.run_bin.assert_has_calls([call("keystore", "remove key1")])
