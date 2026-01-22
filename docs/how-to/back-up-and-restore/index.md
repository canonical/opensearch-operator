---
myst:
  html_meta:
    description: "Complete backup and restore guides for Charmed OpenSearch including S3, Azure storage configuration, and cluster migration."
---

(how-to-guides-back-up-and-restore-index)=
# Back up and restore

This guide contains recommended steps and useful commands for creating and managing backups
to ensure smooth restores.

## Save cluster credentials

For security reasons, charm credentials are not stored inside backups.
So, if you plan to restore to a backup at any point in the future,
you will need the new user password as well as certificates/keys for your existing cluster.

You can retrieve the credentials of the admin user with the following command:

```text
juju run opensearch/leader get-password
Running operation 141 with 1 task
  - task 142 on unit-opensearch-0

Waiting for task 142...
ca-chain: |-
  -----BEGIN CERTIFICATE-----
...
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----
...
  -----END CERTIFICATE-----
password: <pass>
username: admin
```

(how-to-create-a-backup)=
## Create a backup

Prerequisites:

* A cluster with at least three nodes deployed
* Access to an S3-compatible storage
* Configured settings for the S3-compatible storage

Once you have a three-node cluster with configurations set for S3 storage,
check that Charmed OpenSearch is active and idle with `juju status`.

Once Charmed OpenSearch is `active` and `idle`, you can create your first backup
with the `create-backup` command:

```shell
juju run opensearch/leader create-backup
```

<details> <summary> Output example</summary>

```text
Running operation 333 with 1 task
  - task 334 on unit-opensearch-0

Waiting for task 334...
backup-id: "2024-04-25T21:16:26Z"
status: Backup is running.
```

</details>

## List backups

To list your available, failed, and in progress backups:

```shell
juju run opensearch/leader list-backups
```

<details> <summary> Output example</summary>

```text
juju run opensearch/leader list-backups
Running operation 335 with 1 task
  - task 336 on unit-opensearch-0

Waiting for task 336...
backups: |2-
   backup-id           | backup-status
  ------------------------------------
  2024-04-25T21:09:38Z | success
  2024-04-25T21:16:26Z | success
```

</details>

(how-to-restore-a-local-backup)=
## Restore a local backup

To restore a backup that was made from a different cluster, (i.e. cluster migration via restore),
see [How to migrate to a new cluster](how-to-migrate-a-cluster).

Prerequisites:

* Access to an S3-compatible storage
* Configured settings for the S3-compatible storage
* Existing backups in your S3-compatible storage

To restore a backup from the previously returned list, run the restore command
and pass the corresponding `backup-id`:

```shell
juju run opensearch/leader restore backup-id="2024-04-25T21:16:26Z"
```

<details> <summary> Output example</summary>

```text
Running operation 339 with 1 task
  - task 340 on unit-opensearch-0

Waiting for task 340...
backup-id: "2024-04-25T21:16:26Z"
closed-indices: '{''.opensearch-sap-log-types-config'', ''series_index'', ''.plugins-ml-config''}'
status: Restore is complete
```

</details>

If the restore takes too long, the Juju CLI above will time out but the `juju status` command
will show if the charm is still running the restore action or not.

(how-to-migrate-a-cluster)=
## Migrate to a new cluster via backup

Restoring a backup from a previous cluster to a current cluster requires:

* At least 3x Charmed OpenSearch units deployed and running
* Access to an S3-compatible storage
* Configured settings for the S3-compatible storage
* Backups from the previous cluster in your S3-compatible storage

To restore your new cluster to the state of the previous cluster,
run the restore command and pass the correct `backup-id` (from the previous cluster)
to the command:

```shell
juju run opensearch/leader restore backup-id="2024-04-25T21:16:26Z"
```

<details> <summary> Output example</summary>

```text
Running operation 339 with 1 task
  - task 340 on unit-opensearch-0

Waiting for task 340...
backup-id: "2024-04-25T21:16:26Z"
closed-indices: '{''.opensearch-sap-log-types-config'', ''series_index'', ''.plugins-ml-config''}'
status: Restore is complete
```

</details>

```{toctree}
:titlesonly:
:hidden:

Configure Azure Storage <configure-azure-storage>
Configure S3 <configure-s3>
```
