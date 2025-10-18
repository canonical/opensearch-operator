# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

import pytest
from charms.opensearch.v0.constants_charm import AZURE_RELATION, S3_RELATION
from charms.opensearch.v0.models import DeploymentType
from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm
from charms.opensearch.v0.opensearch_distro import OpenSearchDistribution
from charms.opensearch.v0.opensearch_exceptions import OpenSearchHttpError
from charms.opensearch.v0.opensearch_health import HealthColors
from ops import testing

S3_CONN_INFO = {
    "access-key": "ACCESSXXX",
    "secret-key": "secret",
    "bucket": "mybucket",
    "endpoint": "https://s3.example.com",
    "region": "us-east-1",
    "path": "base/path",
}

AZURE_CONN_INFO = {
    "storage_account": "account",
    "secret_key": "key",
    "container": "backups",
    "endpoint": "https://acct.blob.core.windows.net",
    "path": "base/path",
}


def _relation_for_backend(backend: str) -> testing.Relation:
    if backend == "s3":
        return testing.Relation(
            endpoint=S3_RELATION, interface="s3", remote_app_name="s3-integrator"
        )
    elif backend == "azure":
        return testing.Relation(
            endpoint=AZURE_RELATION, interface="azure", remote_app_name="azure-integrator"
        )


def _conn_patch_for_backend(backend: str):
    """Return a patch object that matches object storage connection info."""
    if backend == "s3":
        return patch(
            "charms.data_platform_libs.v0.s3.S3Requirer.get_s3_connection_info",
            return_value=S3_CONN_INFO,
        )

    return patch(
        "charms.data_platform_libs.v0.object_storage.AzureStorageRequires.get_azure_storage_connection_info",
        return_value=AZURE_CONN_INFO,
    )


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_create_backup_action_http_error(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.create_snapshot",
            side_effect=OpenSearchHttpError(response_text="server error", response_code=500),
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st_in)
    assert "backup request failed" in err.value.message.lower()
    assert "server error" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_create_backup_action_success(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.create_snapshot",
            return_value="2025-01-01T10:00:00Z",
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value={"snapshot": "2025-01-01T10:00:00Z", "state": "SUCCESS"},
        ),
    ):
        ctx.run(ctx.on.action("create-backup"), st_in)

    assert ctx.action_results == {
        "backup-id": "2025-01-01T10:00:00Z",
        "status": "SUCCESS",
    }


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_list_backups_json(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})
    snapshots = {
        "2025-01-01T10:00:00Z": {"state": "success", "indices": []},
        "2025-01-01T09:00:00Z": {"state": "failed", "indices": []},
    }

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.list_snapshots",
            return_value=snapshots,
        ),
    ):
        ctx.run(ctx.on.action("list-backups", params={"output": "json"}), st_in)

    assert json.loads(ctx.action_results["backups"]) == snapshots


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_list_backups_table(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})
    snapshots = {
        "2025-01-01T10:00:00Z": {"state": "success", "indices": []},
        "2025-01-01T09:00:00Z": {"state": "in_progress", "indices": []},
    }

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.list_snapshots",
            return_value=snapshots,
        ),
    ):
        ctx.run(ctx.on.action("list-backups", params={"output": "table"}), st_in)

    table = ctx.action_results["backups"]
    assert "backup-id" in table and "backup-status" in table
    assert "2025-01-01T10:00:00Z" in table
    assert "success" in table


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_create_backup_missing_prereqs(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value="you must relate to storage",
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st_in)

    assert "you must relate to storage" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_missing_prereqs(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value="cluster not ready",
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st_in)

    assert "cluster not ready" in err.value.message.lower()


def test_conflicting_storage_relations(metadata, actions, charm_config, mk_ctx):
    ctx = mk_ctx(metadata, actions, charm_config)
    s3_rel = _relation_for_backend("s3")
    # Skip entire test if azure isn't in metadata (helper will skip)
    az_rel = _relation_for_backend("azure")
    st_in = testing.State(leader=True, relations={s3_rel, az_rel})

    with patch(
        "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
        return_value="ambiguous object storage relations",
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("list-backups", params={"output": "json"}), st_in)

    assert "ambiguous" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_not_found(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value=None,
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("restore", params={"backup-id": "X"}), st_in)

    assert "not found" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_get_snapshot_http_error(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            side_effect=OpenSearchHttpError(response_text="server error", response_code=500),
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st_in)

    assert "server error" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
@pytest.mark.parametrize(
    "close_result, expect_fail, expect_msg",
    [
        ((None, None), False, None),
        ((["idx1", "idx2"], None), False, None),
        ((["idx1"], {"idx2": {"closed": False}}), True, "failed to close"),
    ],
)
def test_restore_close_indices_paths(
    metadata, actions, charm_config, mk_ctx, backend, close_result, expect_fail, expect_msg
):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})

    snapshot_doc = {"snapshot": "2025-01-01T10:00:00Z", "state": "SUCCESS"}

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value=snapshot_doc,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            return_value=close_result,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.restore_snapshot",
            return_value=None,
        ),
    ):
        if expect_fail:
            with pytest.raises(testing.ActionFailed) as err:
                ctx.run(
                    ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st_in
                )
            assert expect_msg in err.value.message.lower()
        else:
            ctx.run(ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st_in)
            assert ctx.action_results.get("status") == expect_msg


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_start_fails(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})

    snapshot_doc = {"snapshot": "2025-01-01T10:00:00Z", "state": "SUCCESS"}

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value=snapshot_doc,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            return_value=(None, None),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.restore_snapshot",
            side_effect=OpenSearchHttpError(response_text="restore failed", response_code=409),
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st_in)

    assert "restore failed" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_list_backups_http_error(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st_in = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.list_snapshots",
            side_effect=OpenSearchHttpError(response_text="server error", response_code=503),
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("list-backups", params={"output": "json"}), st_in)

    msg = err.value.message.lower()
    assert "server error" in msg or "503" in msg


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_success(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    snapshot_doc = {"snapshot": "2025-01-01T10:00:00Z", "state": "SUCCESS", "indices": ["idx1"]}

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value=snapshot_doc,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            return_value=(None, None),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.restore_snapshot",
            return_value=set(),
        ),
        patch(
            "charms.opensearch.v0.opensearch_health.OpenSearchHealth.apply", return_value=None
        ) as m_apply,
    ):
        ctx.run(ctx.on.action("restore", params={"backup-id": "2025-01-01T10:00:00Z"}), st)
        # The action doesn't set a result on pure success; just assert we reached health.apply
        assert m_apply.called


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_snapshot_not_found(metadata, actions, charm_config, mk_ctx, backend):
    """If get_snapshot returns None, action fails with 'not found'."""
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value=None,
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("restore", params={"backup-id": "X"}), st)
        assert "not found" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_fails_to_close_indices(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    snapshot_doc = {"snapshot": "S", "state": "SUCCESS", "indices": ["idx1", "idx2"]}

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value=snapshot_doc,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            return_value=(["idx1"], {"idx2": {"closed": False}}),
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("restore", params={"backup-id": "S"}), st)
        assert "failed to close" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_close_indices_http_error(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    snapshot_doc = {"snapshot": "S", "state": "SUCCESS", "indices": ["idx"]}

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value=snapshot_doc,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            side_effect=OpenSearchHttpError(response_text="close-error", response_code=500),
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("restore", params={"backup-id": "S"}), st)
        assert "close" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_start_http_error(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    snapshot_doc = {"snapshot": "S", "state": "SUCCESS"}

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value=snapshot_doc,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            return_value=(None, None),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.restore_snapshot",
            side_effect=OpenSearchHttpError(response_text="restore failed", response_code=409),
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("restore", params={"backup-id": "S"}), st)
        assert "restore failed" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_restore_non_restored_indices(metadata, actions, charm_config, mk_ctx, backend):
    """If some indices didn’t restore, action fails with a count."""
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    snapshot_doc = {"snapshot": "S", "state": "SUCCESS"}

    with (
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents._action_missing_pre_requisites",
            return_value=None,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.get_snapshot",
            return_value=snapshot_doc,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.close_snapshot_indices_open_in_cluster",
            return_value=(None, None),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.restore_snapshot",
            return_value={"a", "b"},
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("restore", params={"backup-id": "S"}), st)
        assert "failed to restore 2 indices" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_prereq_not_leader(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=False, relations={_relation_for_backend(backend)})
    with pytest.raises(testing.ActionFailed) as err:
        ctx.run(ctx.on.action("create-backup"), st)
    assert "leader" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_prereq_deployment_not_ready(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with patch(
        "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
        return_value=None,
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)
    assert "deployment not ready" in err.value.message.lower()


def test_prereq_upgrade_in_progress(metadata, actions, charm_config, mk_ctx):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True)
    with (
        patch(
            "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
            return_value=object(),
        ),
        patch(
            "src.charm.OpenSearchOperatorCharm.upgrade_in_progress",
            new_callable=PropertyMock,
            return_value=True,
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)
    assert "upgrade in-progress" in err.value.message.lower()


def test_prereq_missing_relation(metadata, actions, charm_config, mk_ctx):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True)
    with (
        patch(
            "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
            return_value=object(),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=None,
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)
    assert "missing relation" in err.value.message.lower()


def test_prereq_conflict_detected_from_two_relations(metadata, actions, charm_config, mk_ctx):
    ctx = mk_ctx(metadata, actions, charm_config)
    s3 = testing.Relation(
        endpoint=S3_RELATION,
        interface="s3",
        remote_app_name="s3-integrator",
        remote_app_data={
            "access-key": "AKIEE",
            "secret-key": "secret",
            "bucket": "bkt",
        },
    )
    az = testing.Relation(
        endpoint=AZURE_RELATION,
        interface="azure",
        remote_app_name="azure-integrator",
        remote_app_data={
            "account-name": "account",
            "account-key": "key",
            "container": "cont",
        },
    )
    st = testing.State(leader=True, relations={s3, az})

    with patch(
        "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
        return_value=SimpleNamespace(typ=DeploymentType.MAIN_ORCHESTRATOR),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)

    assert "conflict" in err.value.message.lower()


def test_prereq_conflict_more_than_one_relation_via_property(
    metadata, actions, charm_config, mk_ctx
):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True)
    with (
        patch(
            "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
            return_value=SimpleNamespace(typ=None),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value="conflict",
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)
    assert "conflict" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_prereq_repo_missing_and_cannot_create(metadata, actions, charm_config, mk_ctx, backend):
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
            return_value=object(),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_repository_created",
            side_effect=[False, False],
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.create_repo",
            return_value=None,
        ),
        patch.object(OpenSearchDistribution, "is_node_up", return_value=True),
        patch.object(OpenSearchBaseCharm, "alt_hosts", new_callable=PropertyMock, return_value=[]),
        patch(
            "charms.opensearch.v0.opensearch_health.OpenSearchHealth.get",
            return_value=HealthColors.GREEN,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_snapshot_running",
            return_value=False,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_restore_running",
            return_value=False,
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)
    assert "repository has not been created" in err.value.message.lower()


@pytest.mark.parametrize("backend", ["s3", "azure"])
def test_prereq_http_error_during_precheck(metadata, actions, charm_config, mk_ctx, backend):
    """Any HTTP error in precheck should shown up in the message."""
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
            return_value=object(),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_repository_created",
            side_effect=OpenSearchHttpError(response_text="precheck-failed", response_code=500),
        ),
        patch.object(OpenSearchDistribution, "is_node_up", return_value=True),
        patch(
            "src.charm.OpenSearchOperatorCharm.alt_hosts",
            new_callable=PropertyMock,
            return_value=[],
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)
    assert "precheck-failed" in err.value.message.lower()


@pytest.mark.parametrize(
    "color", [HealthColors.RED, HealthColors.YELLOW_TEMP, HealthColors.UNKNOWN]
)
def test_prereq_health_gates(metadata, actions, charm_config, mk_ctx, color):
    """Health RED/YELLOW_TEMP/UNKNOWN blocks actions with specific messages."""
    backend = "s3"
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
            return_value=object(),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_repository_created",
            return_value=True,
        ),
        patch.object(OpenSearchDistribution, "is_node_up", return_value=True),
        patch.object(OpenSearchBaseCharm, "alt_hosts", new_callable=PropertyMock, return_value=[]),
        patch("charms.opensearch.v0.opensearch_health.OpenSearchHealth.get", return_value=color),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)
    msg = err.value.message.lower()
    assert any(k in msg for k in ["red", "relocating", "unknown"])


def test_prereq_running_operations(metadata, actions, charm_config, mk_ctx):
    """If a snapshot or restore is running, block action with a proper message."""
    backend = "s3"
    ctx = mk_ctx(metadata, actions, charm_config)
    st = testing.State(leader=True, relations={_relation_for_backend(backend)})

    with (
        patch(
            "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
            return_value=object(),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_repository_created",
            return_value=True,
        ),
        patch.object(OpenSearchDistribution, "is_node_up", return_value=True),
        patch.object(OpenSearchBaseCharm, "alt_hosts", new_callable=PropertyMock, return_value=[]),
        patch(
            "charms.opensearch.v0.opensearch_health.OpenSearchHealth.get",
            return_value=HealthColors.GREEN,
        ),
        # simulate running snapshot
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_snapshot_running",
            return_value=True,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_restore_running",
            return_value=False,
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)
        assert "operation in progress" in err.value.message.lower()

    # simulate running restore
    with (
        patch(
            "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
            return_value=object(),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value=backend,
        ),
        _conn_patch_for_backend(backend),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_repository_created",
            return_value=True,
        ),
        patch.object(OpenSearchDistribution, "is_node_up", return_value=True),
        patch.object(OpenSearchBaseCharm, "alt_hosts", new_callable=PropertyMock, return_value=[]),
        patch(
            "charms.opensearch.v0.opensearch_health.OpenSearchHealth.get",
            return_value=HealthColors.GREEN,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_snapshot_running",
            return_value=False,
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsManager.is_restore_running",
            return_value=True,
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)
        assert "operation in progress" in err.value.message.lower()


def test_prereq_conflict_multiple_relations(metadata, actions, charm_config, mk_ctx):
    ctx = mk_ctx(metadata, actions, charm_config)
    s3_rel = _relation_for_backend("s3")
    az_rel = _relation_for_backend("azure")
    st = testing.State(leader=True, relations={s3_rel, az_rel})

    with (
        patch(
            "charms.opensearch.v0.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc",
            return_value=object(),
        ),
        patch(
            "charms.opensearch.v0.opensearch_snapshots.OpenSearchSnapshotsEvents.object_storage_type",
            new_callable=PropertyMock,
            return_value="conflict",
        ),
    ):
        with pytest.raises(testing.ActionFailed) as err:
            ctx.run(ctx.on.action("create-backup"), st)

    assert "conflict" in err.value.message.lower()
