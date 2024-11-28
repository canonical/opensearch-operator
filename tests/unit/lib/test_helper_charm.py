# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, call, mock_open, patch

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.helper_charm import (
    Status,
    _update_dashboard_title,
    mask_sensitive_information,
    update_grafana_dashboards_titles,
)
from ops.model import BlockedStatus, MaintenanceStatus, WaitingStatus
from ops.testing import Harness

from charm import OpenSearchOperatorCharm


class TestHelperDatabag(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.status = self.charm.status

    def test_clear_status(self):
        """Test clearing the charm status."""
        self.charm.unit.status = WaitingStatus("Status Message 1")
        self.status.clear("Status Message 1", pattern=Status.CheckPattern.Equal)
        self.assertEqual(self.charm.unit.status.name, "active")

        self.charm.unit.status = WaitingStatus("Status Message 2")
        self.status.clear("Stat", pattern=Status.CheckPattern.Start)
        self.assertEqual(self.charm.unit.status.name, "active")

        self.charm.unit.status = MaintenanceStatus("Status Message 3")
        self.status.clear("ssage 3", pattern=Status.CheckPattern.End)
        self.assertEqual(self.charm.unit.status.name, "active")

        self.charm.unit.status = BlockedStatus("Status Message 4")
        self.status.clear("essage 4", pattern=Status.CheckPattern.Contain)
        self.assertEqual(self.charm.unit.status.name, "active")

        message_template = "Message {} filled by {}."
        self.charm.unit.status = BlockedStatus(message_template.format(5, "unit tests"))
        self.status.clear(message_template, pattern=Status.CheckPattern.Interpolated)
        self.assertEqual(self.charm.unit.status.name, "active")

    def test_mask_sensitive_information(self):
        """Verify the pattern to remove sensitive information from the logs."""
        command_to_test = """-tspass mypasswd \
        -kspass myother!passwd \
        -storepass another#passwd \
        -new newpasswd% \
        pass:pass&wd,
        """

        expected_result = """-tspass xxx \
        -kspass xxx \
        -storepass xxx \
        -new xxx \
        pass:xxx
        """

        actual_result = mask_sensitive_information(command_to_test)
        assert actual_result == expected_result


class TestCOSGrafanaDashboard(unittest.TestCase):

    @patch("charms.opensearch.v0.helper_charm.get_charm_revision", return_value=167)
    @patch("charms.opensearch.v0.helper_charm.Path.iterdir")
    @patch("charms.opensearch.v0.helper_charm._update_dashboard_title")
    def test_update_grafana_dashboards_titles(self, mock_update_dashboard, mock_iterdir, _):
        mock_charm = MagicMock()
        mock_charm.model.unit = MagicMock()
        type(mock_charm).charm_dir = PropertyMock(return_value=Path("/fake/charm/dir"))

        mock_json_file_1 = MagicMock(spec=Path)
        mock_json_file_1.is_file.return_value = True
        mock_json_file_1.suffix = ".json"
        mock_json_file_1.name = "dashboard1.json"

        mock_non_json_file = MagicMock(spec=Path)
        mock_non_json_file.is_file.return_value = True
        mock_non_json_file.suffix = ".txt"
        mock_non_json_file.name = "not_a_dashboard.txt"

        mock_json_file_2 = MagicMock(spec=Path)
        mock_json_file_2.is_file.return_value = True
        mock_json_file_2.suffix = ".json"
        mock_json_file_2.name = "dashboard2.json"

        mock_iterdir.return_value = [mock_json_file_1, mock_non_json_file, mock_json_file_2]

        update_grafana_dashboards_titles(mock_charm)

        # non-json files are not called
        mock_update_dashboard.assert_has_calls(
            [
                call(167, mock_json_file_1),
                call(167, mock_json_file_2),
            ],
            any_order=True,
        )

        self.assertEqual(mock_update_dashboard.call_count, 2)

    @patch("charms.opensearch.v0.helper_charm.get_charm_revision", return_value=167)
    @patch("charms.opensearch.v0.helper_charm.logger")
    @patch("charms.opensearch.v0.helper_charm.Path.iterdir")
    @patch("charms.opensearch.v0.helper_charm._update_dashboard_title")
    def test_update_grafana_dashboards_titles_json_exception(
        self, mock_update_dashboard, mock_iterdir, mock_logger, _
    ):
        mock_charm = MagicMock()
        mock_charm.model.unit = MagicMock()
        type(mock_charm).charm_dir = PropertyMock(return_value=Path("/fake/charm/dir"))

        mock_json_file_1 = MagicMock(spec=Path)
        mock_json_file_1.is_file.return_value = True
        mock_json_file_1.suffix = ".json"
        mock_json_file_1.name = "dashboard1.json"

        mock_iterdir.return_value = [mock_json_file_1]

        mock_update_dashboard.side_effect = json.JSONDecodeError("Error", "Error", 0)

        update_grafana_dashboards_titles(mock_charm)

        mock_logger.error.assert_called_once()

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps({"title": "Charmed OpenSearch"}),
    )
    @patch("json.dump")
    def test_update_dashboard_title_no_prior_revision(self, mock_json_dump, mock_open_func):

        _update_dashboard_title(167, MagicMock())

        expected_updated_dashboard = {"title": "Charmed OpenSearch - Rev 167"}
        mock_json_dump.assert_called_once_with(
            expected_updated_dashboard, mock_open_func(), indent=4
        )

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps({"title": "Charmed OpenSearch - Rev 166"}),
    )
    @patch("json.dump")
    def test_update_dashboard_title_prior_revision(
        self,
        mock_json_dump,
        mock_open_func,
    ):

        _update_dashboard_title("167", MagicMock())

        expected_updated_dashboard = {"title": "Charmed OpenSearch - Rev 167"}
        mock_json_dump.assert_called_once_with(
            expected_updated_dashboard, mock_open_func(), indent=4
        )

    @patch("charms.opensearch.v0.helper_charm.logger")
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps({"my-content": "content"}),
    )
    @patch("json.dump")
    def test_update_dashboard_title_json_no_title(
        self,
        _,
        __,
        mock_logger,
    ):

        _update_dashboard_title("167", MagicMock())

        mock_logger.warning.assert_called_once()
