# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cos library."""

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, call, mock_open, patch

from charms.opensearch.v0.helper_cos import (
    _update_dashboard_title,
    update_grafana_dashboards_titles,
)


class TestCOSGrafanaDashboard(unittest.TestCase):

    @patch("charms.opensearch.v0.helper_cos.get_charm_revision", return_value=167)
    @patch("charms.opensearch.v0.helper_cos.Path.iterdir")
    @patch("charms.opensearch.v0.helper_cos._update_dashboard_title")
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

    @patch("charms.opensearch.v0.helper_cos.get_charm_revision", return_value=167)
    @patch("charms.opensearch.v0.helper_cos.logger")
    @patch("charms.opensearch.v0.helper_cos.Path.iterdir")
    @patch("charms.opensearch.v0.helper_cos._update_dashboard_title")
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

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps({"my-content": "content"}),
    )
    @patch("json.dump")
    def test_update_dashboard_title_json_no_title(
        self,
        mock_json_dump,
        mock_open_func,
    ):

        _update_dashboard_title("167", MagicMock())

        expected_updated_dashboard = {
            "title": "Charmed OpenSearch - Rev 167",
            "my-content": "content",
        }
        mock_json_dump.assert_called_once_with(
            expected_updated_dashboard, mock_open_func(), indent=4
        )
