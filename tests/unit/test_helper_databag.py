# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import unittest

from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from charms.opensearch.v0.helper_cluster import ClusterTopology, Node
from charms.opensearch.v0.helper_databag import SecretStore


class TestHelperDatabag(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.secret_store = SecretStore()

    def test_put(self):
        """Test"""
        pass

    def test_put_object(self):
        pass

    def test_get(self):
        pass

    def test_get_object(self):
        pass

    def test_delete(self):
        pass
