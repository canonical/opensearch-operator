---
myst:
  html_meta:
    description: "Configure SMTP credentials for Charmed OpenSearch email notifications using the SMTP integrator charm."
---

(how-to-guides-add-smtp-credentials)=
# How to enable email notifications

This guide shows how to configure SMTP credentials so that OpenSearch can send email notifications
via the [SMTP integrator charm](https://charmhub.io/smtp-integrator).

```{note}
SMTP servers using self-signed certificates are not currently supported.
```

## Deploy and configure the SMTP integrator

Deploy the charm:

```shell
juju deploy smtp-integrator --channel latest/edge
```

The charm will be `blocked` until configured. Provide SMTP credentials:

```shell
juju config smtp-integrator \
  host=<smtp-host> \
  port=587 \
  user=<smtp-username> \
  password=<smtp-password> \
  smtp-sender=<sender-email> \
  recipients=<recipient-1>,<recipient-2>
```

## Integrate with OpenSearch

```shell
juju integrate smtp-integrator:smtp opensearch:smtp
```

```{note}
OpenSearch requires a stable identifier for each email sender, notification channel, and
notification group. The charm derives this identifier from the Juju relation ID of the
SMTP integration, so the relation ID must remain stable. If you remove and re-add the
integration, OpenSearch treats each reconnection as a new sender and channel, and the
previous entries become stale. See the
[OpenSearch Notifications documentation](https://docs.opensearch.org/2.19/observing-your-data/notifications/index/#create-email-sender)
for details.
```

### Large deployments

In large deployments, the SMTP integrator must be integrated with the **main orchestrator** application.

Identify the main orchestrator by inspecting `juju status` integrations:

```text
Integration provider                           Requirer                                Interface           Type     Message
opensearch-main:peer-cluster-orchestrator      opensearch-data:peer-cluster            peer_cluster        regular  
```

Integrate with the main orchestrator:

```shell
juju integrate smtp-integrator:smtp opensearch-main
```

If integrated with the wrong application, the charm shows a `blocked` status.
Remove the invalid relation and integrate with the correct application.

## Expected result

`juju status --relations` shows the `smtp-integrator` and `opensearch` applications `active`, with an
`smtp` relation between them. OpenSearch notification channels can now send email via the
configured SMTP server.

## Next steps

* [Enable monitoring (COS)](how-to-monitoring) — set up alerting and observability for the cluster.
* [Access OpenSearch using OAuth](how-to-access-using-oauth) — configure authentication for client access.
