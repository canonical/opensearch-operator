(how-to-guides-add-smtp-credentials)=
# How to add SMTP credentials to enable email notifications

This document describes how to configure SMTP credentials using the SMTP integrator charm so that OpenSearch can automatically create and manage Notifications email sender, channel, and group configurations.

```{note}
Sending emails through an SMTP server that uses self-signed certificates is not currently supported.
```

## Deploy the SMTP integrator

The SMTP credentials are provided to OpenSearch via the SMTP integrator charm.

Deploy the charm:

```shell
juju deploy smtp-integrator --channel latest/edge
```

After deployment, the charm will report a blocked status until configuration values are provided.
You can confirm this with `juju status`:

```shell
App                       Version  Status   Scale  Charm                     Channel      Rev  Exposed  Message
opensearch                         active       3  opensearch                               0  no
self-signed-certificates           active       1  self-signed-certificates  1/stable     317  no
smtp-integrator                    blocked      1  smtp-integrator           latest/edge   98  no       invalid configuration: host

Unit                         Workload  Agent  Machine  Public address  Ports     Message
opensearch/0*                active    idle   0        10.45.114.28    9200/tcp
opensearch/1                 active    idle   1        10.45.114.254   9200/tcp
opensearch/2                 active    idle   2        10.45.114.38    9200/tcp
self-signed-certificates/0*  active    idle   3        10.45.114.130
smtp-integrator/0*           blocked   idle   4        10.45.114.15              invalid configuration: host
```

Configure the SMTP integrator with SMTP credentials:

```shell
juju config smtp-integrator \
  host="<smtp-host>" \
  port="587" \
  user="<smtp-username>" \
  password="<smtp-password>" \
  smtp-sender="<sender-email>" \
  recipients="a@example.com,b@example.com"
```

**Important**
The [OpenSearch documentation](https://docs.opensearch.org/2.19/observing-your-data/notifications/index/#create-email-sender) requires the SMTP integration relation ID when creating an email sender. 
The relation ID is used to derive the OpenSearch SMTP sender config, the email channel and the email recipient group.
## Integrate the SMTP integrator and OpenSearch

Integrate the SMTP integrator with the OpenSearch application:

```shell
juju integrate smtp-integrator:smtp opensearch:smtp
```

## Large Deployments

In large deployments, the SMTP integrator must be integrated with the main orchestrator application.

You can identify which applications is the main-orchestrator
by inspecting the `integrations` section of `juju status`:

```shell
Integration provider                           Requirer                                Interface           Type     Message
opensearch-main:peer-cluster-orchestrator      opensearch-data:peer-cluster            peer_cluster        regular  
```

Integrate the SMTP integrator with this application:

```shell
juju integrate smtp-integrator:smtp opensearch-main
```

If the SMTP integrator is related with an application other than the main orchestrator,
you will see a `blocked` status message similar to:

```shell
App                       Version  Status   Scale  Charm                     Channel        Rev  Exposed  Message
opensearch-data                    blocked      1  opensearch                                 2  no       SMTP relation must be created with the main-orchestrator cluster.
opensearch-failover                active       1  opensearch                                 1  no
opensearch-main                    active       1  opensearch                                 0  no
self-signed-certificates           active       1  self-signed-certificates  latest/stable  264  no
smtp-integrator                    active       1  smtp-integrator           latest/stable   93  no
```

Remove the invalid relation and integrate with the main orchestrator application to resolve the issue.
