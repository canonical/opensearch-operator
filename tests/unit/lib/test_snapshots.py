# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from azure.core.exceptions import AzureError, ResourceNotFoundError
from botocore.exceptions import ClientError
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_snapshots import (
    OpenSearchSnapshotsManager as SnapshotsManager,
)
from google.api_core.exceptions import Conflict, Forbidden
from ops import testing

from lib.charms.opensearch.v0 import helper_security
from tests.unit.lib.fixtures_snapshots import SnapshotsUnitTestFixtures

_S3_PEM = """-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUTestFakeCertForUnitTestsOnly1234567890
-----END CERTIFICATE-----"""

S3_CONN_INFO_WITH_CA = {
    "access-key": "ACCESS",
    "secret-key": "secret",
    "bucket": "mybucket",
    "endpoint": "https://s3.example.com",
    "region": "us-east-1",
    "path": "base/path",
    "tls_ca_chain": _S3_PEM,
}


class TestCreateBackup(SnapshotsUnitTestFixtures):
    def test_create_backup_when_manager_raises_http_error_then_action_fails(self, backend_setup):
        backend, rels = backend_setup
        st = testing.State(leader=True, relations=rels)
        self.mock_create_snapshot.side_effect = OpenSearchHttpError(
            response_text="server error", response_code=500
        )

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        msg = err.value.message.lower()
        assert "backup request failed" in msg
        assert "server error" in msg or "500" in msg

    def test_create_backup_when_all_ok_then_success_result_is_returned(self, backend_setup):
        backend, rels = backend_setup
        st = testing.State(leader=True, relations=rels)

        self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert self.ctx.action_results == {
            "backup-id": "2025-01-01T10:00:00Z",
            "status": "success",
        }

    def test_create_backup_when_s3_repo_missing_and_ca_present_then_raise_repository_missing_error(
        self,
    ):
        ca = "-----BEGIN CERT-----\nMIIB...==\n-----END CERT-----\n"
        self.use_s3(ca=ca)
        self.mock_is_repo_created.return_value = False

        st = testing.State(
            leader=True,
            relations={self.s3_relation()},
        )

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "The opensearch repository could not be created yet." in str(err.value)

        self.mock_create_snapshot.assert_not_called()

    def test_create_backup_when_s3_has_no_ca_then_operations_still_succeed(self):
        s3_no_ca = {k: v for k, v in S3_CONN_INFO_WITH_CA.items() if k != "tls_ca_chain"}
        self.use_s3(info=s3_no_ca)
        st = testing.State(leader=True, relations={self.s3_relation()})

        self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert self.ctx.action_results == {
            "backup-id": "2025-01-01T10:00:00Z",
            "status": "success",
        }


class TestListBackups(SnapshotsUnitTestFixtures):
    def test_list_backups_when_json_requested_then_json_is_returned(self, backend_setup):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)
        snapshots = {
            "2025-01-01T10:00:00Z": {"state": "success", "indices": []},
            "2025-01-01T09:00:00Z": {"state": "failed", "indices": []},
        }

        original = SnapshotsManager.list_snapshots
        SnapshotsManager.list_snapshots = lambda *_a, **_k: snapshots
        try:
            self.ctx.run(self.ctx.on.action("list-backups", params={"output": "json"}), st)
        finally:
            SnapshotsManager.list_snapshots = original

        assert json.loads(self.ctx.action_results["backups"]) == snapshots

    def test_list_backups_when_table_requested_then_table_is_returned(self, backend_setup):
        backend, rels = backend_setup
        st = testing.State(leader=True, relations=rels)
        snapshots = {
            "2025-01-01T10:00:00Z": {"state": "success", "indices": []},
            "2025-01-01T09:00:00Z": {"state": "in_progress", "indices": []},
        }

        original = SnapshotsManager.list_snapshots
        SnapshotsManager.list_snapshots = lambda *_a, **_k: snapshots
        try:
            self.ctx.run(self.ctx.on.action("list-backups", params={"output": "table"}), st)
        finally:
            SnapshotsManager.list_snapshots = original

        table = self.ctx.action_results["backups"]
        assert "backup-id" in table and "backup-status" in table
        assert "2025-01-01T10:00:00Z" in table
        assert "success" in table

    def test_list_backups_when_manager_raises_http_error_then_action_fails(self, backend_setup):
        backend, rels = backend_setup
        st = testing.State(leader=True, relations=rels)

        self.mock_get_snapshot.side_effect = None
        original = SnapshotsManager.list_snapshots

        def return_error(*_a, **_k):
            raise OpenSearchHttpError(response_text="server error", response_code=503)

        SnapshotsManager.list_snapshots = return_error

        try:
            with pytest.raises(testing.ActionFailed) as err:
                self.ctx.run(self.ctx.on.action("list-backups", params={"output": "json"}), st)
        finally:
            SnapshotsManager.list_snapshots = original

        msg = err.value.message.lower()
        assert "server error" in msg or "503" in msg

    def test_list_backups_when_not_leader_then_action_fails(self, backend_setup):
        backend, rels = backend_setup

        st = testing.State(leader=False, relations=rels)

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("list-backups", params={"output": "json"}), st)

        assert "leader" in err.value.message.lower()


class TestRestore(SnapshotsUnitTestFixtures):
    def test_restore_when_prereqs_missing_then_action_fails(self, backend_setup, monkeypatch):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)

        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotEvents._action_missing_pre_requisites",
            lambda _self, report_running_operations=True: "cluster not ready",
        )

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(
                self.ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st
            )

        assert "cluster not ready" in err.value.message.lower()

    def test_restore_when_snapshot_not_found_then_action_fails(self, backend_setup):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)
        self.mock_get_snapshot.return_value = None

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("restore", params={"backup-id": "X"}), st)

        assert "not found" in err.value.message.lower()

    def test_restore_when_get_snapshot_http_error_then_action_fails(self, backend_setup):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)
        self.mock_get_snapshot.side_effect = OpenSearchHttpError(
            response_text="server error", response_code=500
        )
        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(
                self.ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st
            )

        assert "server error" in err.value.message.lower()

    @pytest.mark.parametrize(
        "close_result, expect_fail, expect_msg",
        [
            ((None, None), False, None),
            ((["idx1", "idx2"], None), False, None),
            ((["idx1"], {"idx2": {"closed": False}}), True, "failed to close"),
        ],
    )
    def test_restore_when_closing_indices_varies_then_paths_are_handled(
        self, backend_setup, close_result, expect_fail, expect_msg, monkeypatch
    ):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)
        self.mock_get_snapshot.return_value = {
            "snapshot": "2025-01-01T10:00:00Z",
            "state": "SUCCESS",
        }

        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            lambda *_a, **_k: close_result,
        )
        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.restore_snapshot",
            lambda *_a, **_k: None,
        )

        if expect_fail:
            with pytest.raises(testing.ActionFailed) as err:
                self.ctx.run(
                    self.ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st
                )
            assert expect_msg in err.value.message.lower()
        else:
            self.ctx.run(
                self.ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st
            )

    def test_restore_when_start_fails_then_action_fails_with_message(
        self, backend_setup, monkeypatch
    ):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)
        self.mock_get_snapshot.return_value = {
            "snapshot": "2025-01-01T10:00:00Z",
            "state": "SUCCESS",
        }

        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            lambda *_a, **_k: (None, None),
        )

        def return_error(*_a, **_k):
            raise OpenSearchHttpError(response_text="restore failed", response_code=409)

        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.restore_snapshot",
            return_error,
        )

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(
                self.ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st
            )
        assert "restore failed" in err.value.message.lower()

    def test_restore_when_non_restored_indices_exist_then_action_fails_with_count(
        self, backend_setup, monkeypatch
    ):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)
        self.mock_get_snapshot.return_value = {"snapshot": "S", "state": "SUCCESS"}

        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            lambda *_a, **_k: (None, None),
        )
        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.restore_snapshot",
            lambda *_a, **_k: {"a", "b"},
        )

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("restore", params={"backup-id": "S"}), st)
        assert "failed to restore 2 indices" in err.value.message.lower()

    def test_restore_when_http_error_on_close_indices_then_action_fails(
        self, backend_setup, monkeypatch
    ):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)
        self.mock_get_snapshot.return_value = {
            "snapshot": "S",
            "state": "SUCCESS",
            "indices": ["idx"],
        }

        def return_error(*_a, **_k):
            raise OpenSearchHttpError(response_text="close-error", response_code=500)

        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            return_error,
        )

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("restore", params={"backup-id": "S"}), st)
        assert "close" in err.value.message.lower()

    def test_restore_when_all_ok_then_health_apply_is_called(self, backend_setup, monkeypatch):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)
        self.mock_get_snapshot.return_value = {
            "snapshot": "2025-01-01T10:00:00Z",
            "state": "SUCCESS",
            "indices": ["idx1"],
        }

        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            lambda *_a, **_k: (None, None),
        )
        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.restore_snapshot",
            lambda *_a, **_k: set(),
        )

        called = {"ok": False}

        def fake_apply(*_a, **_k):
            called["ok"] = True

        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_health.OpenSearchHealth.apply",
            lambda *_a, **_k: fake_apply(),
        )
        self.ctx.run(
            self.ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st
        )
        assert called["ok"]

    def test_restore_when_not_leader_then_action_fails(self, backend_setup):
        backend, rels = backend_setup

        st = testing.State(leader=False, relations=rels)

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(
                self.ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st
            )

        assert "leader" in err.value.message.lower()


class TestPrerequisites(SnapshotsUnitTestFixtures):
    def test_prereq_when_not_leader_then_action_fails(self, backend_setup):
        backend, rels = backend_setup

        st = testing.State(leader=False, relations=rels)

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "leader" in err.value.message.lower()

    def test_prereq_when_deployment_not_ready_then_action_fails(self, backend_setup, monkeypatch):
        backend, rels = backend_setup

        self.mock_deployment_desc.return_value = None

        st = testing.State(leader=True, relations=rels)

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "deployment not ready" in err.value.message.lower()

    def test_prereq_when_upgrade_in_progress_then_action_fails(self, monkeypatch):
        st = testing.State(leader=True)
        monkeypatch.setattr(
            "src.charm.OpenSearchOperatorCharm.upgrade_in_progress",
            property(lambda _self: True),
        )

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "upgrade in-progress" in err.value.message.lower()

    def test_prereq_when_storage_relation_missing_then_action_fails(self, monkeypatch):
        st = testing.State(leader=True)
        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "missing relation" in err.value.message.lower()

    def test_prereq_when_conflict_detected_from_two_relations_then_action_fails(self, monkeypatch):
        st = testing.State(leader=True, relations={self.s3_relation(), self.azure_relation()})
        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "conflict" in err.value.message.lower()

    def test_prereq_when_repo_missing_and_cannot_create_then_action_fails(
        self, backend_setup, monkeypatch
    ):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)

        self.mock_is_repo_created.side_effect = [False, False]
        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.create_repository",
            lambda *_a, **_k: None,
        )
        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "repository could not be created" in err.value.message.lower()

    def test_prereq_when_http_error_during_repo_check_then_error_message_displayed(
        self, backend_setup, monkeypatch
    ):
        backend, rels = backend_setup

        st = testing.State(leader=True, relations=rels)

        def return_error(*_a, **_k):
            raise OpenSearchHttpError(response_text="precheck-failed", response_code=500)

        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_repository_created",
            return_error,
        )

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "precheck-failed" in err.value.message.lower()

    @pytest.mark.parametrize(
        "color", [HealthColors.RED, HealthColors.YELLOW_TEMP, HealthColors.UNKNOWN]
    )
    def test_prereq_when_health_not_green_then_action_fails_with_specific_message(self, color):
        self.use_s3()
        st = testing.State(leader=True, relations={self.s3_relation()})
        self.mock_is_repo_created.return_value = True
        self.mock_health_get.return_value = color

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        msg = err.value.message.lower()
        assert any(k in msg for k in ["red", "relocating", "unknown"])

    def test_prereq_when_snapshot_or_restore_running_then_action_fails(self):
        self.use_s3()
        st = testing.State(leader=True, relations={self.s3_relation()})

        self.mock_is_repo_created.return_value = True
        self.mock_health_get.return_value = HealthColors.GREEN
        self.mock_backup_running.return_value = True
        self.mock_restore_running.return_value = False

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)
        assert "operation in progress" in err.value.message.lower()

        self.mock_backup_running.return_value = False
        self.mock_restore_running.return_value = True

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)
        assert "operation in progress" in err.value.message.lower()


class TestCreateS3Bucket(SnapshotsUnitTestFixtures):
    @staticmethod
    def _client_error(code: str, status: int = 400) -> ClientError:
        return ClientError(
            {
                "Error": {"Code": code, "Message": "err"},
                "ResponseMetadata": {"HTTPStatusCode": status},
            },
            operation_name="Test",
        )

    def test_create_s3_bucket_when_region_non_us_east_1_but_no_aws_endpoint_then_does_not_call_location_constraint(
        self, monkeypatch
    ):
        bucket = Mock()
        bucket.wait_until_exists = Mock()

        get_bucket = Mock(return_value=bucket)
        monkeypatch.setattr(helper_security, "get_s3_bucket_resource", get_bucket)

        params = {
            "access-key": "a",
            "secret-key": "s",
            "bucket": "b",
            "endpoint": "https://s3.example",
            "region": "eu-north-1",
        }

        helper_security.create_s3_bucket(params, verify=True)

        get_bucket.assert_called_once()
        bucket.create.assert_called_once_with()
        bucket.wait_until_exists.assert_called_once()

    def test_create_s3_bucket_when_region_non_us_east_1_with_aws_endpoint_then_call_location_constraint(
        self, monkeypatch
    ):
        bucket = Mock()
        bucket.wait_until_exists = Mock()

        get_bucket = Mock(return_value=bucket)
        monkeypatch.setattr(helper_security, "get_s3_bucket_resource", get_bucket)

        params = {
            "access-key": "a",
            "secret-key": "s",
            "bucket": "b",
            "endpoint": "amazonaws.com",
            "region": "eu-north-1",
        }

        helper_security.create_s3_bucket(params, verify=True)

        get_bucket.assert_called_once()
        bucket.create.assert_called_once_with(
            CreateBucketConfiguration={"LocationConstraint": "eu-north-1"}
        )
        bucket.wait_until_exists.assert_called_once()

    def test_create_s3_bucket_when_region_us_east_1_then_calls_create_without_location_constraint(
        self, monkeypatch
    ):
        bucket = Mock()
        bucket.wait_until_exists = Mock()

        monkeypatch.setattr(helper_security, "get_s3_bucket_resource", lambda *_a, **_k: bucket)

        params = {
            "access-key": "a",
            "secret-key": "s",
            "bucket": "b",
            "endpoint": "https://s3.example",
            "region": "us-east-1",
        }

        helper_security.create_s3_bucket(params, verify=True)

        bucket.create.assert_called_once_with()
        bucket.wait_until_exists.assert_called_once()

    @pytest.mark.parametrize(
        "code", ["BucketAlreadyOwnedByYou", "BucketAlreadyExists", "BucketNameUnavailable"]
    )
    def test_create_s3_bucket_when_bucket_already_exists_then_it_does_not_raise(
        self, monkeypatch, code
    ):
        bucket = Mock()
        bucket.create.side_effect = self._client_error(code)

        monkeypatch.setattr(helper_security, "get_s3_bucket_resource", lambda *_a, **_k: bucket)

        params = {
            "access-key": "a",
            "secret-key": "s",
            "bucket": "b",
            "endpoint": "https://s3.example",
            "region": "us-east-1",
        }
        helper_security.create_s3_bucket(params, verify=True)

    def test_create_s3_bucket_when_access_denied_then_other_clienterror_raises(self, monkeypatch):
        bucket = Mock()
        bucket.create.side_effect = self._client_error("AccessDenied", status=403)

        monkeypatch.setattr(helper_security, "get_s3_bucket_resource", lambda *_a, **_k: bucket)

        params = {
            "access-key": "a",
            "secret-key": "s",
            "bucket": "b",
            "endpoint": "https://s3.example",
            "region": "us-east-1",
        }

        with pytest.raises(ClientError):
            helper_security.create_s3_bucket(params, verify=True)

    def test_verify_s3_credentials_when_bucket_missing_then_triggers_create_and_probe(
        self, monkeypatch
    ):
        cfg = Mock()
        cfg.s3 = Mock()
        cfg.s3.credentials = Mock()
        cfg.s3.tls_ca_chain = None
        cfg.s3.credentials.access_key = "a"
        cfg.s3.credentials.secret_key = "s"
        cfg.s3.bucket = "mybucket"
        cfg.s3.endpoint = "https://s3.example"
        cfg.s3.region = "us-east-1"
        cfg.s3.base_path = "base/path"

        bucket = Mock()
        bucket.meta = Mock()
        bucket.meta.client = Mock()

        # head_bucket returns 404 (NoSuchBucket)
        bucket.meta.client.head_bucket.side_effect = self._client_error("NoSuchBucket", status=404)

        # probe write/delete
        bucket.put_object = Mock()
        bucket.Object.return_value.delete = Mock()

        monkeypatch.setattr(helper_security, "get_s3_bucket_resource", lambda *_a, **_k: bucket)

        mock_create = Mock(return_value=None)
        monkeypatch.setattr(helper_security, "create_s3_bucket", mock_create)

        ok = helper_security.verify_s3_credentials(cfg)
        assert ok is True

        mock_create.assert_called_once()
        bucket.put_object.assert_called_once()
        bucket.Object.return_value.delete.assert_called_once()


class TestCreateAzureContainer(SnapshotsUnitTestFixtures):
    def test_create_azure_container_when_create_bucket_then_create_container_is_called(
        self, monkeypatch
    ):
        client = Mock()
        monkeypatch.setattr(helper_security, "get_azure_container_client", lambda _params: client)

        params = {
            "storage-account": "acc",
            "secret-key": "key",
            "container": "cont",
            "account-url": "https://acc.blob.core.windows.net",
        }

        helper_security.create_azure_container(params)
        client.create_container.assert_called_once()

    def test_create_azure_container_when_container_exists_and_we_run_create_container_then_it_does_not_raise(
        self, monkeypatch
    ):
        client = Mock()
        client.create_container.side_effect = AzureError("boom")
        monkeypatch.setattr(helper_security, "get_azure_container_client", lambda _params: client)

        params = {
            "storage-account": "acc",
            "secret-key": "key",
            "container": "cont",
            "account-url": "https://acc.blob.core.windows.net",
        }

        with pytest.raises(AzureError):
            helper_security.create_azure_container(params)

    def test_create_azure_container_when_create_container_then_other_azure_error_raises(
        self, monkeypatch
    ):
        client = Mock()
        client.create_container.side_effect = AzureError("boom")
        monkeypatch.setattr(helper_security, "get_azure_container_client", lambda _params: client)

        params = {
            "storage-account": "acc",
            "secret-key": "key",
            "container": "cont",
            "account-url": "https://acc.blob.core.windows.net",
        }

        with pytest.raises(AzureError):
            helper_security.create_azure_container(params)

    def test_create_azure_container_when_container_missing_then_triggers_create_and_probe(
        self, monkeypatch
    ):
        cfg = Mock()
        cfg.azure = Mock()
        cfg.azure.credentials = Mock()
        cfg.azure.connection_protocol = "https"
        cfg.azure.credentials.storage_account = "acc"
        cfg.azure.credentials.secret_key = "key"
        cfg.azure.container = "cont"
        cfg.azure.base_path = "base/path"
        cfg.azure.endpoint = "https://account.blob.core.windows.net/container"

        container_client = Mock()
        container_client.get_container_properties.side_effect = ResourceNotFoundError("missing")

        blob_client = Mock()
        container_client.get_blob_client.return_value = blob_client

        monkeypatch.setattr(
            helper_security, "get_azure_container_client", lambda _params: container_client
        )

        mock_create = Mock(return_value=None)
        monkeypatch.setattr(helper_security, "create_azure_container", mock_create)

        ok = helper_security.verify_azure_credentials(cfg)
        assert ok is True

        mock_create.assert_called_once()
        blob_client.upload_blob.assert_called_once()
        blob_client.delete_blob.assert_called_once()


class TestCreateGCSBucket(SnapshotsUnitTestFixtures):
    @staticmethod
    def _cfg(*, secret_key: str = "{}", bucket: str = "bkt", base_path: str = "base/path"):
        """Build an ObjectStorageConfig mock for GCS."""
        cfg = Mock()
        cfg.gcs = Mock()
        cfg.gcs.credentials = Mock()
        cfg.gcs.credentials.secret_key = secret_key
        cfg.gcs.bucket = bucket
        cfg.gcs.base_path = base_path
        return cfg

    def test_create_gcs_bucket_when_credentials_block_missing_then_return_false(self):
        cfg = Mock()
        cfg.gcs = Mock()
        cfg.gcs.credentials = None

        assert helper_security.verify_gcs_credentials(cfg) is False

    def test_create_gcs_bucket_when_secret_key_empty_then_return_false(self):
        cfg = self._cfg(secret_key="")
        assert helper_security.verify_gcs_credentials(cfg) is False

    def test_create_gcs_bucket_when_bucket_name_empty_then_return_false(self):
        cfg = self._cfg(bucket="")
        assert helper_security.verify_gcs_credentials(cfg) is False

    def test_create_gcs_bucket_when_secret_key_is_invalid_json_then_return_false(self):
        cfg = self._cfg(secret_key="not-json")
        assert helper_security.verify_gcs_credentials(cfg) is False

    def test_create_gcs_bucket_when_bucket_missing_then_create_bucket_test_write_access(
        self, monkeypatch
    ):
        cfg = self._cfg(
            secret_key='{"project_id":"p"}',
            bucket="mybucket",
            base_path="base/path",
        )

        client = Mock()
        bucket = Mock()
        blob = Mock()

        bucket.exists.return_value = False
        bucket.blob.return_value = blob

        monkeypatch.setattr(helper_security, "get_gcs_client", lambda _json: client)
        monkeypatch.setattr(helper_security, "get_gcs_bucket", lambda _client, _name: bucket)

        create_bucket = Mock(return_value=None)
        monkeypatch.setattr(helper_security, "create_gcs_bucket", create_bucket)

        monkeypatch.setattr(helper_security.uuid, "uuid4", lambda: Mock(hex="abc"))

        ok = helper_security.verify_gcs_credentials(cfg)
        assert ok is True

        create_bucket.assert_called_once_with(client, bucket)
        bucket.blob.assert_called_once_with("base/path/.opensearch-verify-abc")
        blob.upload_from_string.assert_called_once()
        blob.delete.assert_called_once()

    def test_create_gcs_bucket_when_exists_check_forbidden_then_attempt_to_create(
        self, monkeypatch
    ):
        cfg = self._cfg(secret_key='{"project_id":"p"}', bucket="mybucket")

        client = Mock()
        bucket = Mock()
        blob = Mock()

        bucket.exists.side_effect = Forbidden("no buckets.get")
        bucket.blob.return_value = blob

        monkeypatch.setattr(helper_security, "get_gcs_client", lambda _json: client)
        monkeypatch.setattr(helper_security, "get_gcs_bucket", lambda _client, _name: bucket)

        create_bucket = Mock(return_value=None)
        monkeypatch.setattr(helper_security, "create_gcs_bucket", create_bucket)

        ok = helper_security.verify_gcs_credentials(cfg)
        assert ok is True
        create_bucket.assert_called_once_with(client, bucket)

    @pytest.mark.parametrize("exc", [Conflict("taken"), Forbidden("denied")])
    def test_create_gcs_bucket_when_bucket_creation_fails_then_return_false(
        self, monkeypatch, exc
    ):
        cfg = self._cfg(secret_key='{"project_id":"p"}', bucket="mybucket")

        client = Mock()
        bucket = Mock()
        bucket.exists.return_value = False

        monkeypatch.setattr(helper_security, "get_gcs_client", lambda _json: client)
        monkeypatch.setattr(helper_security, "get_gcs_bucket", lambda _client, _name: bucket)

        def _raise(*_a, **_k):
            raise exc

        monkeypatch.setattr(helper_security, "create_gcs_bucket", _raise)

        assert helper_security.verify_gcs_credentials(cfg) is False

    def test_create_gcs_bucket_when_probe_upload_forbidden_then_return_false(self, monkeypatch):
        cfg = self._cfg(
            secret_key='{"project_id":"p"}',
            bucket="mybucket",
            base_path="base/path",
        )
        client = Mock()
        bucket = Mock()
        blob = Mock()
        bucket.exists.return_value = True
        bucket.blob.return_value = blob
        blob.upload_from_string.side_effect = Forbidden("no objects.create")

        monkeypatch.setattr(helper_security, "get_gcs_client", lambda _json: client)
        monkeypatch.setattr(helper_security, "get_gcs_bucket", lambda _client, _name: bucket)
        assert helper_security.verify_gcs_credentials(cfg) is False
        blob.delete.assert_not_called()
