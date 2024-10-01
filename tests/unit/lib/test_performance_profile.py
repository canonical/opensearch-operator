# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import MagicMock, mock_open, patch

from charms.opensearch.v0.models import OpenSearchPerfProfile, PerformanceType
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


def test_perf_profile_15g():
    """Test the performance profile for a 5GB machine.

    Each profile type must respect their respective values.
    """
    with patch("charms.opensearch.v0.models.OpenSearchPerfProfile.meminfo") as mock_perf_profile:
        mock_perf_profile.return_value = {"MemTotal": ("15360", "mB")}

        profile = OpenSearchPerfProfile.from_str("production")
        assert profile.typ == PerformanceType.PRODUCTION
        assert str(profile.heap_size) == "3840m"
        assert profile.opensearch_yml == {"indices.memory.index_buffer_size": "25%"}
        assert profile.charmed_index_template == {
            "charmed-index-tpl": {
                "index_patterns": ["*"],
                "template": {"settings": {"number_of_replicas": "1-all"}},
            }
        }

        profile = OpenSearchPerfProfile.from_str("staging")
        assert profile.typ == PerformanceType.STAGING
        assert str(profile.heap_size) == "1536m"
        assert profile.charmed_index_template == {
            "charmed-index-tpl": {
                "index_patterns": ["*"],
                "template": {"settings": {"number_of_replicas": "1-all"}},
            }
        }
        assert profile.opensearch_yml == {"indices.memory.index_buffer_size": "25%"}

        profile = OpenSearchPerfProfile.from_str("testing")
        assert profile.typ == PerformanceType.TESTING
        assert str(profile.heap_size) == "1g"
        assert profile.charmed_index_template == {}
        assert profile.opensearch_yml == {}


def test_perf_profile_5g():
    """Test the performance profile for a 5GB machine.

    In this case, we should expect the on "staging" to be smaller than 1GB, therefore, to select
    the 1GB value instead.
    """
    with patch("charms.opensearch.v0.models.OpenSearchPerfProfile.meminfo") as mock_perf_profile:
        mock_perf_profile.return_value = {"MemTotal": ("5120", "mB")}

        profile = OpenSearchPerfProfile.from_str("production")
        assert profile.typ == PerformanceType.PRODUCTION
        assert str(profile.heap_size) == "1280m"
        assert profile.opensearch_yml == {"indices.memory.index_buffer_size": "25%"}
        assert profile.charmed_index_template == {
            "charmed-index-tpl": {
                "index_patterns": ["*"],
                "template": {"settings": {"number_of_replicas": "1-all"}},
            }
        }

        profile = OpenSearchPerfProfile.from_str("staging")
        assert profile.typ == PerformanceType.STAGING
        assert str(profile.heap_size) == "1g"
        assert profile.charmed_index_template == {
            "charmed-index-tpl": {
                "index_patterns": ["*"],
                "template": {"settings": {"number_of_replicas": "1-all"}},
            }
        }
        assert profile.opensearch_yml == {"indices.memory.index_buffer_size": "25%"}

        profile = OpenSearchPerfProfile.from_str("testing")
        assert profile.typ == PerformanceType.TESTING
        assert str(profile.heap_size) == "1g"
        assert profile.charmed_index_template == {}
        assert profile.opensearch_yml == {}


# We need to simulate the original value of jvm.options
JVM_OPTIONS = """-Xms1g
-Xmx1g"""

MEMINFO = """MemTotal:        15360 mB
MemFree:          1234 kB
NotValid:         0
"""


class TestPerformanceProfile(unittest.TestCase):

    def setUp(self):
        with patch("builtins.open", mock_open(read_data=MEMINFO)):
            self.harness = Harness(OpenSearchOperatorCharm)
            self.addCleanup(self.harness.cleanup)
            self.harness.set_leader(True)
            self.harness.begin()
            self.charm = self.harness.charm
            self.opensearch = self.charm.opensearch
            self.test_profile = OpenSearchPerfProfile.from_str("production")

    @patch("charms.opensearch.v0.helper_conf_setter.exists")
    def test_update_jvm_options(self, _):
        """Test the update of the JVM options."""
        with patch("builtins.open", mock_open(read_data=JVM_OPTIONS)) as m_open:
            mock_write = m_open.return_value.__enter__.return_value.write = MagicMock()
            self.charm.opensearch_config.apply_performance_profile(profile=self.test_profile)

            mock_write.assert_any_call("-Xms3840m\n-Xmx1g")
            mock_write.assert_any_call("-Xms1g\n-Xmx3840m")
