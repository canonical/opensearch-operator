# How to create a backup

This guide contains recommended steps and useful commands for creating and managing backups to ensure smooth restores:

* Save your current cluster credentials, as you’ll need them for restoring
* Create backups
* List backups to check the availability and status of your backups

[note]All commands are written for juju >= v3.1.7[/note]

For more information, check the [Juju Release Notes](https://juju.is/docs/juju/roadmap#heading--juju-releases).

## Prerequisites

* A cluster with at least three nodes deployed
* Access to an S3-compatible storage
* Configured settings for the S3-compatible storage

## Save your current cluster credentials

For security reasons, charm credentials are not stored inside backups. So, if you plan to restore to a backup at any point in the future, you will need the new user password as well as certificates/keys for your existing cluster.

You can retrieve the credentials of the admin user with the following command:

```
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

For more context about passwords during a restore, check How to restore an external backup.

## Create backups

Once you have a three-nodes cluster with configurations set for S3 storage, check that Charmed OpenSearch is active and idle with juju status.

Once Charmed OpenSearch is active and idle, you can create your first backup with the create-backup command:

```
juju run opensearch/leader create-backup
Running operation 333 with 1 task
  - task 334 on unit-opensearch-0

Waiting for task 334...
backup-id: "2024-04-25T21:16:26Z"
status: Backup is running.
```

## List backups

You can list your available, failed, and in progress backups by running the list-backups command:

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