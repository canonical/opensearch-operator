---
myst:
  html_meta:
    description: "Set up Google Cloud Storage for Charmed OpenSearch backups using the GCS Integrator charm and configure integration."
---

(how-to-back-up-configure-gcs-storage)=
# How to configure Google Cloud Storage

This guide shows how to configure the
[GCS Integrator charm](https://charmhub.io/gcs-integrator) for OpenSearch backups.

## Prepare the Google Cloud service account

In your Google Cloud project, create a service account and download its JSON key:

```shell
gcloud iam service-accounts create opensearch-backup
gcloud iam service-accounts keys create service-account.json \
    iam.gserviceaccount.com/opensearch-backup@<project-id>.iam.gserviceaccount.com
```

Grant the service account permission to list, read, and write objects in the bucket:

```shell
gcloud projects add-iam-policy-binding <project-id> \
    --member=serviceAccount:opensearch-backup@<project-id>.iam.gserviceaccount.com \
    --role=roles/storage.objectAdmin
```

```{note}
If the bucket does not exist yet, Charmed OpenSearch creates it during credential
verification, which also requires permission to create buckets in the project
(`roles/storage.admin`). Bucket names in Google Cloud Storage are globally unique.
```

## Deploy and configure the integrator

Deploy the charm:

```shell
juju deploy gcs-integrator --channel 1/stable
```

Store the service-account key in a
[Juju secret](https://canonical-juju.readthedocs-hosted.com/en/latest/user/reference/secret/)
and grant access to the integrator:

```shell
juju add-secret gcs-secret secret-key#file=service-account.json
juju grant-secret gcs-secret gcs-integrator
```

The `#file=` suffix tells Juju to read the value from the local file rather than from the
command-line argument, keeping the private key out of your shell history.

```{note}
Charmed OpenSearch accepts service-account keys as plain JSON or base64-encoded JSON, so
no decoding is required.
```

Point the integrator at the secret and configure the bucket:

```shell
juju config gcs-integrator \
    credentials=secret:<secret-id> \
    bucket=<bucket-name> \
    path=<path>
```

See the [gcs-integrator configuration reference](https://charmhub.io/gcs-integrator/configuration)
for all available options.

## Integrate with Charmed OpenSearch

Connect the integrator to OpenSearch:

```shell
juju integrate gcs-integrator opensearch
```

Once the integration is established, `juju status --relations` shows the `gcs-integrator`
application `active` with a `gcs-credentials` relation to `opensearch`. The OpenSearch
application remains `active`.

```{caution}
Only one object storage integrator can be related at a time. Relating both the GCS
integrator and the S3 or Azure Storage integrator places OpenSearch in a `blocked` state
with the message `Too many object storage relations. Only one is supported.` until you
remove the extra relations.
```

## Next steps

* [Create and restore backups](how-to-create-a-backup) — create a backup using the configured Google Cloud Storage.
* [Configure S3 storage](how-to-back-up-configure-s3) — alternative storage backend.
* [Configure Azure storage](how-to-back-up-configure-azure-storage) — alternative storage backend.
