# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
from __future__ import annotations

import json

import pytest
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_health import HealthColors
from charms.opensearch.v0.opensearch_snapshots import (
    OpenSearchSnapshotsManager as SnapshotsManager,
)
from ops import testing

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
    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_create_backup_when_manager_raises_http_error_then_action_fails(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

        st = testing.State(leader=True, relations=rels)
        self.mock_create_snapshot.side_effect = OpenSearchHttpError(
            response_text="server error", response_code=500
        )

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        msg = err.value.message.lower()
        assert "backup request failed" in msg
        assert "server error" in msg or "500" in msg

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_create_backup_when_all_ok_then_success_result_is_returned(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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
    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_list_backups_when_json_requested_then_json_is_returned(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_list_backups_when_table_requested_then_table_is_returned(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_list_backups_when_manager_raises_http_error_then_action_fails(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_list_backups_when_not_leader_then_action_fails(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

        st = testing.State(leader=False, relations=rels)

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("list-backups", params={"output": "json"}), st)

        assert "leader" in err.value.message.lower()


class TestRestore(SnapshotsUnitTestFixtures):
    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_restore_when_prereqs_missing_then_action_fails(self, backend, monkeypatch):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_restore_when_snapshot_not_found_then_action_fails(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

        st = testing.State(leader=True, relations=rels)
        self.mock_get_snapshot.return_value = None

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("restore", params={"backup-id": "X"}), st)

        assert "not found" in err.value.message.lower()

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_restore_when_get_snapshot_http_error_then_action_fails(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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
    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_restore_when_closing_indices_varies_then_paths_are_handled(
        self, backend, close_result, expect_fail, expect_msg, monkeypatch
    ):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_restore_when_start_fails_then_action_fails_with_message(self, backend, monkeypatch):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_restore_when_non_restored_indices_exist_then_action_fails_with_count(
        self, backend, monkeypatch
    ):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_restore_when_http_error_on_close_indices_then_action_fails(
        self, backend, monkeypatch
    ):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_restore_when_all_ok_then_health_apply_is_called(self, backend, monkeypatch):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_restore_when_not_leader_then_action_fails(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

        st = testing.State(leader=False, relations=rels)

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(
                self.ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st
            )

        assert "leader" in err.value.message.lower()


class TestPrerequisites(SnapshotsUnitTestFixtures):
    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_prereq_when_not_leader_then_action_fails(self, backend):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

        st = testing.State(leader=False, relations=rels)

        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "leader" in err.value.message.lower()

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_prereq_when_deployment_not_ready_then_action_fails(self, backend, monkeypatch):
        if backend == "s3":
            self.use_s3()
            relations = {self.s3_relation()}
        else:
            self.use_azure()
            relations = {self.azure_relation()}

        self.mock_deployment_desc.return_value = None

        st = testing.State(leader=True, relations=relations)

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

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_prereq_when_repo_missing_and_cannot_create_then_action_fails(
        self, backend, monkeypatch
    ):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

        st = testing.State(leader=True, relations=rels)

        self.mock_is_repo_created.side_effect = [False, False]
        monkeypatch.setattr(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.create_repository",
            lambda *_a, **_k: None,
        )
        with pytest.raises(testing.ActionFailed) as err:
            self.ctx.run(self.ctx.on.action("create-backup"), st)

        assert "repository could not be created" in err.value.message.lower()

    @pytest.mark.parametrize("backend", ["s3", "azure"])
    def test_prereq_when_http_error_during_repo_check_then_error_message_displayed(
        self, backend, monkeypatch
    ):
        if backend == "s3":
            self.use_s3()
            rels = {self.s3_relation()}
        else:
            self.use_azure()
            rels = {self.azure_relation()}

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
