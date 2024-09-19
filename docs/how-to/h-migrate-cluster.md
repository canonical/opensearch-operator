[note]All commands are written for `juju v.3.1.7+`[/note]

# How to migrate to a new cluster via restore

This is a guide on how to restore a backup that was made from a different cluster, (i.e. cluster migration via restore).

To perform a basic restore (from a local backup), see [How to restore a local backup](/t/14099).

## Prerequisites

Restoring a backup from a previous cluster to a current cluster requires:
* At least 3x Charmed OpenSearch units deployed and running
* Access to an S3-compatible storage
* Configured settings for the S3-compatible storage
* Backups from the previous cluster in your S3-compatible storage

---

## List backups

To view the available backups to restore, use the command `list-backups`:

```none
juju run opensearch/leader list-backups
Running operation 335 with 1 task
  - task 336 on unit-opensearch-0

Waiting for task 336...
backups: |2-
   backup-id           | backup-status
  ------------------------------------
  2024-04-25T21:09:38Z | success
  2023-12-08T21:16:26Z | success
```

## Restore backup

To restore your current cluster to the state of the previous cluster, run the `restore` command and pass the correct `backup-id` (from the previously returned list) to the command:

```none
juju run opensearch/leader restore backup-id="2024-04-25T21:16:26Z"
Running operation 339 with 1 task
  - task 340 on unit-opensearch-0

Waiting for task 340...
backup-id: "2024-04-25T21:16:26Z"
closed-indices: '{''.opensearch-sap-log-types-config'', ''series_index'', ''.plugins-ml-config''}'
status: Restore is complete
```

Your backup has been restored.

If the restore takes too long, the Juju CLI above will time out but the `juju status` command will provide a view if the charm is still running the restore action or not.