---
myst:
  html_meta:
    description: "Back up and restore Charmed OpenSearch including S3 and Azure storage configuration, and cluster migration."
---

(how-to-guides-back-up-and-restore-index)=
# How to back up and restore

This guide shows how to create backups of a Charmed OpenSearch cluster,
restore from a backup, and migrate data to a new cluster.

## Prerequisites

* A cluster with at least three nodes deployed and `active`
* Access to S3-compatible or Azure storage (see [Configure S3](how-to-back-up-configure-s3)
  or [Configure Azure storage](how-to-back-up-configure-azure-storage))
* Storage integration already established with OpenSearch

## Save cluster credentials

Backups exclude the security configuration, so the source cluster's users, passwords, and
role mappings cannot be restored. Before you run a restore or migrate to a new cluster,
save the admin password and the CA certificates of the target cluster:

```shell
juju run opensearch/leader get-password
```

```{caution}
Excluding the security configuration does not protect the data itself. The snapshot
repository still contains all indexed application data in an unencrypted form. Anyone with
access to the repository can register it in another compatible OpenSearch cluster and
restore that data using their own cluster's admin credentials. Protect the repository with
strict access controls and encryption at rest.
```

(how-to-create-a-backup)=
## Create a backup

Confirm the cluster is `active` and `idle` with `juju status`, then run:

```shell
juju run opensearch/leader create-backup
```

Once the backup completes, it appears in `list-backups` with a `success` status.

## List backups

To list available, failed, and in-progress backups:

```shell
juju run opensearch/leader list-backups
```

<details>
<summary>Output example</summary>

```text
backup-id            | backup-status
-------------------------------------
2026-01-01T10:30:00Z | in_progress
2026-01-01T10:00:00Z | success
2026-01-01T09:00:00Z | failed
```

</details>

(how-to-restore-a-local-backup)=
## Restore a backup

To restore a backup that was made from a different cluster (cluster migration),
see [Migrate to a new cluster](#how-to-migrate-a-cluster) below.

To restore from the same cluster, pass the `backup-id` from `list-backups`:

```shell
juju run opensearch/leader restore backup-id=<backup-id>
```

After the restore completes, `juju status` shows the OpenSearch application `active` and
the cluster health API returns `green`.

```{note}
If the restore takes longer than the Juju CLI timeout, it continues in the background.
Monitor progress with `juju status`.
```

(how-to-migrate-a-cluster)=
## Migrate to a new cluster

To migrate data from one cluster to another, configure the new cluster to use the
same storage backend where the old cluster's backups reside, then restore:

```shell
juju run opensearch/leader restore backup-id=<backup-id>
```

The `<backup-id>` must reference a backup created by the previous cluster.

## Next steps

* [Upgrade, rollback, and recover](how-to-minor-upgrade) — upgrade the cluster after restoring.
* [Manage persistent storage](how-to-persistent-storage) — reuse disks when no viable snapshot exists.

```{toctree}
:titlesonly:
:hidden:

Configure Azure Storage <configure-azure-storage>
Configure S3 <configure-s3>
```
