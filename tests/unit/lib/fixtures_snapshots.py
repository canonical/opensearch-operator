# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

import pytest
from charms.opensearch.v0.constants_charm import AZURE_RELATION, S3_RELATION
from charms.opensearch.v0.models import (
    DeploymentType,
)
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_health import HealthColors
from ops import testing

from src.charm import OpenSearchOperatorCharm

DEFAULT_S3_INFO = {
    "access-key": "ACCESS",
    "secret-key": "secret",
    "bucket": "mybucket",
    "endpoint": "https://s3.example.com",
    "region": "us-east-1",
    "path": "base/path",
}

DEFAULT_AZURE_INFO = {
    "storage_account": "account",
    "secret_key": "key",
    "container": "backups",
    "endpoint": "https://acct.blob.core.windows.net",
    "path": "base/path",
}


class SnapshotsUnitTestFixtures:
    """Test fixtures for the OpenSearch snapshots tests."""

    patch_deployment_desc = patch(
        "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
        return_value=SimpleNamespace(typ=DeploymentType.MAIN_ORCHESTRATOR),
    )
    patch_is_node_up = patch.object(OpenSearchDistribution, "is_node_up", return_value=True)
    patch_alt_hosts = patch(
        "src.charm.OpenSearchOperatorCharm.alt_hosts", new_callable=PropertyMock
    )

    patch_s3_conn = patch(
        "charms.data_platform_libs.v0.s3.S3Requirer.get_s3_connection_info",
        return_value=DEFAULT_S3_INFO,
    )
    patch_az_conn = patch(
        "charms.data_platform_libs.v0.azure_storage.AzureStorageRequires.get_azure_storage_connection_info",
        return_value=DEFAULT_AZURE_INFO,
    )

    patch_is_repo_created = patch(
        "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_repository_created",
        return_value=True,
    )
    patch_health_get = patch(
        "charms.opensearch.v0.opensearch_health.OpenSearchHealth.get",
        return_value=HealthColors.GREEN,
    )
    patch_backup_running = patch(
        "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_snapshot_in_progress",
        return_value=False,
    )
    patch_restore_running = patch(
        "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_restore_in_progress",
        return_value=False,
    )
    patch_create_snapshot = patch(
        "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.create_snapshot",
        return_value="2025-01-01T10:00:00Z",
    )
    patch_get_snapshot = patch(
        "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
        return_value={"snapshot": "2025-01-01T10:00:00Z", "state": "success"},
    )

    @pytest.fixture(autouse=True)
    def setup(self, request):
        # Start patches
        self.mock_deployment_desc = self.patch_deployment_desc.start()
        self.mock_is_node_up = self.patch_is_node_up.start()
        self.mock_alt_hosts = self.patch_alt_hosts.start()
        self.mock_s3_conn = self.patch_s3_conn.start()
        self.mock_az_conn = self.patch_az_conn.start()
        self.mock_is_repo_created = self.patch_is_repo_created.start()
        self.mock_health_get = self.patch_health_get.start()
        self.mock_backup_running = self.patch_backup_running.start()
        self.mock_restore_running = self.patch_restore_running.start()
        self.mock_create_snapshot = self.patch_create_snapshot.start()
        self.mock_get_snapshot = self.patch_get_snapshot.start()

        self.mock_alt_hosts.return_value = []
        self.use_s3()

        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown():
        patch.stopall()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(charm_type=OpenSearchOperatorCharm)

    def use_s3(self, *, ca: str | None = None, info: dict[str, str] | None = None) -> None:
        """Configure fixture to behave as if S3 is connected, optionally inject a CA."""
        info = info or DEFAULT_S3_INFO
        if ca is not None:
            info["tls_ca_chain"] = ca

        self.mock_s3_conn.return_value = info

    def use_azure(self, info: dict | None = None) -> None:
        """Configure fixture to behave as if Azure is connected."""
        info = info or DEFAULT_AZURE_INFO
        self.mock_az_conn.return_value = info

    @staticmethod
    def s3_relation() -> testing.Relation:
        return testing.Relation(
            endpoint=S3_RELATION, interface="s3", remote_app_name="s3-integrator"
        )

    @staticmethod
    def azure_relation() -> testing.Relation:
        return testing.Relation(
            endpoint=AZURE_RELATION, interface="azure", remote_app_name="azure-integrator"
        )
