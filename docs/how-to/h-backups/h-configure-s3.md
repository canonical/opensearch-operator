[note]All commands are written for `juju >= v.3.1.7 `[/note]

# How to configure S3 storage 

This guide will teach you how to deploy and configure the [S3 Integrator charm](https://charmhub.io/s3-integrator) for [AWS S3](https://aws.amazon.com/s3/), send the configurations to the Charmed OpenSearch application, and update it. The same procedure can be extended to use Ceph RadosGW.

---

## Configure S3 for AWS

First, deploy and run the [`s3-integrator`](https://charmhub.io/s3-integrator) charm:

```shell
juju deploy s3-integrator
juju run s3-integrator/leader sync-s3-credentials \
    access-key=<access-key-here> secret-key=<secret-key-here>
```

>See all other configuration parameters in the [Configuration section](https://charmhub.io/s3-integrator/configuration)  of the s3-integrator documentation.

[note] The Amazon S3 endpoint must be specified as `s3.<region>.amazonaws.com` within the first 24 hours of creating the bucket. For older buckets, the endpoint `s3.amazonaws.com` can be used. See [this AWS forum post](https://repost.aws/knowledge-center/s3-http-307-response) for more information. [/note]

## Configure S3 for Ceph RadosGW

First, deploy and run the [`s3-integrator`](https://charmhub.io/s3-integrator) charm:

```shell
juju deploy s3-integrator

juju run s3-integrator/leader \
    sync-s3-credentials \
    access-key=<access-key-here> \
    secret-key=<secret-key-here>
```

>Ceph can be configured with a custom `region` name, or set as `default` if none was chosen. See the Ceph docs for More information about [RadosGW configuration](https://docs.ceph.com/en/latest/man/8/radosgw-admin/).

Then, use `juju config` to add your configuration parameters. For example:

```shell
juju config s3-integrator \
    endpoint="https://<CEPH_RADOSGW_URL>" \
    bucket="<bucket_name>" \
    path="<path_to_instance>" \
    region="<region>"
```

## Integrate with Charmed OpenSearch

To pass these configurations to Charmed OpenSearch, integrate the two applications:

```shell
juju integrate s3-integrator opensearch
```