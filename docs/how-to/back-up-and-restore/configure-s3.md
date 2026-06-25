---
myst:
  html_meta:
    description: "Configure AWS S3 or Ceph RadosGW storage for Charmed OpenSearch backups using the S3 Integrator charm with Juju."
---

(how-to-back-up-configure-s3)=
# How to configure S3 storage 

This guide shows how to configure the
[S3 Integrator charm](https://charmhub.io/s3-integrator) for OpenSearch backups,
using either AWS S3 or Ceph RadosGW.

## Configure S3 for AWS

Deploy the `s3-integrator` charm and provide credentials:

```shell
juju deploy s3-integrator
juju run s3-integrator/leader sync-s3-credentials \
    access-key=<access-key> secret-key=<secret-key>
```

Configure the bucket and endpoint:

```shell
juju config s3-integrator \
    bucket=<bucket-name> \
    region=<region> \
    endpoint=s3.<region>.amazonaws.com
```

```{note}
The endpoint must be specified as `s3.<region>.amazonaws.com` within the first 24 hours
of creating the bucket. For older buckets, `s3.amazonaws.com` can be used.
See [this AWS knowledge centre article](https://repost.aws/knowledge-center/s3-http-307-response).
```

See the [s3-integrator configuration reference](https://charmhub.io/s3-integrator/configuration)
for all available options.

## Configure S3 for Ceph RadosGW

Deploy the `s3-integrator` charm and provide credentials:

```shell
juju deploy s3-integrator
juju run s3-integrator/leader sync-s3-credentials \
    access-key=<access-key> secret-key=<secret-key>
```

Configure the endpoint and bucket:

```shell
juju config s3-integrator \
    endpoint="https://<radosgw-url>" \
    bucket=<bucket-name> \
    path=<path> \
    region=<region>
```

```{note}
Set `region` to `default` if no custom region was configured in Ceph.
See the [RadosGW documentation](https://docs.ceph.com/en/latest/man/8/radosgw-admin/)
for details.
```

## Integrate with Charmed OpenSearch

Connect the s3-integrator to OpenSearch:

```shell
juju integrate s3-integrator opensearch
```
