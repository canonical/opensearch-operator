(how-to-guides-back-up-and-restore-restore-a-local-backup)=
# Restore a local backup

```{note}All commands are written for `juju v.3.1.7+````

# How to restore a local backup
This is a guide on how to restore a locally made backup.

To restore a backup that was made from a different cluster, (i.e. cluster migration via restore), see [How to migrate to a new cluster](/how-to-guides/back-up-and-restore/migrate-a-cluster).

## Prerequisites
* Access to an S3-compatible storage
* Configured settings for the S3-compatible storage
* Existing backups in your S3-compatible storage

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
