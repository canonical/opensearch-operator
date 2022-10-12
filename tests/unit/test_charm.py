# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest

from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
