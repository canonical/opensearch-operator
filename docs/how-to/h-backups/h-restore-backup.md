# How to restore a local backup
This is a guide on how to restore a locally made backup.

To restore a backup that was made from a different cluster, (i.e. cluster migration via restore), see [How to migrate to a new cluster](/t/14100).

[note]
All commands are written for juju >= v.3.1.7

For more information, check the [Juju Release Notes](https://juju.is/docs/juju/roadmap#heading--juju-releases).
[/note]

## Prerequisites

* Access to an S3-compatible storage
* Configured settings for the S3-compatible storage
* Existing backups in your S3-compatible storage

## List backups

To view the available backups to restore, use the command list-backups:

```
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

## Restore backup

To restore a backup from the previously returned list, run the restore command and pass the corresponding backup-id:

```
juju run opensearch/leader restore backup-id="2024-04-25T21:16:26Z"
Running operation 339 with 1 task
  - task 340 on unit-opensearch-0

Waiting for task 340...
backup-id: "2024-04-25T21:16:26Z"
closed-indices: '{''.opensearch-sap-log-types-config'', ''series_index'', ''.plugins-ml-config''}'
status: Restore is complete
```

Your restore has been restored.

If the restore takes too long, the Juju CLI above will time out but the `juju status` command will provide a view if the charm is still running the restore action or not.