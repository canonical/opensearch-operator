# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cos library."""

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, mock_open, patch

from charms.opensearch.v0.helper_cos import update_grafana_dashboards_title


class TestCOSGrafanaDashboard(unittest.TestCase):

    @patch("charms.opensearch.v0.helper_cos.get_charm_revision", return_value=167)
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps({"title": "Charmed OpenSearch"}),
    )
    @patch("json.dump")
    def test_update_grafana_dashboards_title_no_prior_revision(
        self, mock_json_dump, mock_open_func, _
    ):
        mock_charm = MagicMock()
        mock_charm.model.unit = MagicMock()
        type(mock_charm).charm_dir = PropertyMock(return_value=Path("/fake/charm/dir"))

        update_grafana_dashboards_title(mock_charm)

        expected_updated_dashboard = {"title": "Charmed OpenSearch - Rev 167"}
        mock_json_dump.assert_called_once_with(
            expected_updated_dashboard, mock_open_func(), indent=4
        )

    @patch("charms.opensearch.v0.helper_cos.get_charm_revision", return_value=167)
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps({"title": "Charmed OpenSearch - Rev 166"}),
    )
    @patch("json.dump")
    def test_update_grafana_dashboards_title_prior_revision(
        self,
        mock_json_dump,
        mock_open_func,
        _,
    ):
        mock_charm = MagicMock()
        mock_charm.model.unit = MagicMock()
        type(mock_charm).charm_dir = PropertyMock(return_value=Path("/fake/charm/dir"))

        update_grafana_dashboards_title(mock_charm)

        expected_updated_dashboard = {"title": "Charmed OpenSearch - Rev 167"}
        mock_json_dump.assert_called_once_with(
            expected_updated_dashboard, mock_open_func(), indent=4
        )

    @patch("charms.opensearch.v0.helper_cos.get_charm_revision", return_value=167)
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data=json.dumps({"my-content": "content"}),
    )
    @patch("json.dump")
    def test_update_grafana_dashboards_title_json_no_title(
        self,
        mock_json_dump,
        mock_open_func,
        _,
    ):
        mock_charm = MagicMock()
        mock_charm.model.unit = MagicMock()
        type(mock_charm).charm_dir = PropertyMock(return_value=Path("/fake/charm/dir"))
        update_grafana_dashboards_title(mock_charm)

        expected_updated_dashboard = {
            "title": "Charmed OpenSearch - Rev 167",
            "my-content": "content",
        }
        mock_json_dump.assert_called_once_with(
            expected_updated_dashboard, mock_open_func(), indent=4
        )
