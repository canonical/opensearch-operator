# How to configure S3 storage

A Charmed OpenSearch backup can be stored on any S3-compatible storage. S3 access and configurations are managed with the [s3-integrator charm](https://charmhub.io/s3-integrator).

This guide will teach you how to deploy and configure the s3-integrator charm for [AWS S3](https://aws.amazon.com/s3/), send the configurations to the Charmed OpenSearch application, and update it. The same procedure can be extended to use Ceph RadosGW.

[note]All commands are written for juju >= v.3.1.7 [/note]

For more information, check the [Juju Release Notes](https://juju.is/docs/juju/roadmap#heading--juju-releases).

## Configure s3-integrator

First, deploy and run the charm:

```
juju deploy s3-integrator
juju run s3-integrator/leader sync-s3-credentials \
    access-key=<access-key-here> secret-key=<secret-key-here>
```

There are other options in s3-integrator and [reviewing its configuration docs](https://charmhub.io/s3-integrator/configuration) or [main docs](https://discourse.charmhub.io/t/s3-integrator-documentation/10947) is strongly recommended.

[note] For example, the amazon S3 endpoint must be specified as s3.<region>.amazonaws.com within the first 24 hours of creating the bucket. For older buckets, the endpoint s3.amazonaws.com can be used. See [this post](https://repost.aws/knowledge-center/s3-http-307-response) for more information. [/note]

## Configure S3 for Ceph RadosGW

First, deploy and run the charm, the same way:

```
juju deploy s3-integrator

juju run s3-integrator/leader \
    sync-s3-credentials \
    access-key=<access-key-here> \
    secret-key=<secret-key-here>
```

Ceph can be configured with a custom “region” name, or set as “default” if none was chosen. [More information about in RadosGW configuration.](https://docs.ceph.com/en/latest/man/8/radosgw-admin/)

Then, use juju config to add your configuration parameters. For example:

```
juju config s3-integrator \
    endpoint="https://<CEPH_RADOSGW_URL>" \
    bucket="<bucket_name>" \
    path="<path_to_instance>" \
    region="<region>"
```

## Integrate with Charmed OpenSearch

To pass these configurations to Charmed OpenSearch, integrate the two applications:

juju integrate s3-integrator opensearch