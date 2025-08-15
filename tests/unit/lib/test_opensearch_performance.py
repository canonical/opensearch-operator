# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
from charms.opensearch.v0.opensearch_profile import (
    _1GB_IN_KB,
    ClusterTopologyRequirements,
    ProductionProfile,
    ProfileMemoryRequirements,
    TestingProfile,
)


@pytest.fixture
def mock_meminfo():
    with patch("charms.opensearch.v0.opensearch_distro.OpenSearchDistribution.meminfo") as mock:
        mock.return_value = {"MemTotal": 8000000}  # 8 GB in kB
        yield mock


def test_production_profile():
    production_profile = ProductionProfile()
    assert production_profile.memory_requirements == ProfileMemoryRequirements(
        memory_size=4 * _1GB_IN_KB
    )
    assert production_profile.cluster_topology_requirements == ClusterTopologyRequirements(
        cluster_managers=3, data=3
    )


def test_testing_profile():
    testing_profile = TestingProfile()
    assert testing_profile.memory_requirements == ProfileMemoryRequirements(memory_size=None)
    assert testing_profile.cluster_topology_requirements == ClusterTopologyRequirements(
        cluster_managers=1, data=1
    )


# We need to simulate the original value of jvm.options
JVM_OPTIONS = """-Xms1g
-Xmx1g"""

MEMINFO = """MemTotal:        15728640 kB
MemFree:          1234 kB
NotValid:         0
"""


# class TestPerformanceProfile(unittest.TestCase):

#     def setUp(self):
#         with patch("builtins.open", mock_open(read_data=MEMINFO)):
#             self.harness = Harness(OpenSearchOperatorCharm)
#             self.addCleanup(self.harness.cleanup)
#             self.harness.set_leader(True)
#             self.harness.begin()
#             self.charm = self.harness.charm
#             self.opensearch = self.charm.opensearch
#             self.test_profile = ProductionProfile()

#     @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.replace")
#     @patch("charms.opensearch.v0.helper_conf_setter.YamlConfigSetter.put")
#     @patch("charms.opensearch.v0.helper_conf_setter.exists")
#     def test_update_jvm_options(self, _, __, mock_replace):
#         """Test the update of the JVM options."""
#         self.charm.opensearch_config.set_jvm_heap_size(self.test_profile.memory_requirements.jvm_heap_percentage*)
#         mock_replace.assert_any_call(
#             "jvm.options", "-Xms[0-9]+[kmgKMG]", "-Xms7864320k", regex=True
#         )
#         mock_replace.assert_any_call(
#             "jvm.options", "-Xmx[0-9]+[kmgKMG]", "-Xmx7864320k", regex=True
#         )
