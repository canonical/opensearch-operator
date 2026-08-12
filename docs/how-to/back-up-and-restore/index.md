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

Credentials are not stored in backups — this is intentional so that access to the storage
backend does not grant access to the cluster data. Before you run a restore or migrate to a
new cluster, save the admin password and the CA certificates of the target cluster:

```shell
juju run opensearch/leader get-password
```

(how-to-create-a-backup)=
## Create a backup

Confirm the cluster is `active` and `idle` with `juju status`, then run:

```shell
juju run opensearch/leader create-backup
```

## List backups

To list available, failed, and in-progress backups:

```shell
juju run opensearch/leader list-backups
```

(how-to-restore-a-local-backup)=
## Restore a backup

To restore a backup that was made from a different cluster (cluster migration),
see [Migrate to a new cluster](#how-to-migrate-a-cluster) below.

To restore from the same cluster, pass the `backup-id` from `list-backups`:

```shell
juju run opensearch/leader restore backup-id=<backup-id>
```

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

## Expected result

After creating a backup, `list-backups` shows the new backup with an `available` status.
After restoring, `juju status` shows the OpenSearch application `active` and the cluster health
API returns `green`.

## Next steps

* [Upgrade, rollback, and recover](how-to-minor-upgrade) — upgrade the cluster after restoring.
* [Manage persistent storage](how-to-persistent-storage) — reuse disks when no viable snapshot exists.

```{toctree}
:titlesonly:
:hidden:

Configure Azure Storage <configure-azure-storage>
Configure S3 <configure-s3>
```
