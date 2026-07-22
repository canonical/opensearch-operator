---
myst:
  html_meta:
    description: "Enable monitoring for Charmed OpenSearch by integrating with COS Lite bundle, Grafana, Loki, and Prometheus."
---

(how-to-monitoring)=
# How to enable monitoring (COS)

This guide shows how to integrate Charmed OpenSearch with the
Canonical Observability Stack (COS) for metrics, dashboards, alerts, and logs.

For background on monitoring features, see the [Monitoring explanation](explanation-monitoring).

## Prerequisites

* A deployed [Charmed OpenSearch cluster](tutorial-2-deploy-opensearch)
* A deployed [`cos-lite` bundle in a Kubernetes environment](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s)

## Offer COS interfaces

Switch to the COS K8s controller and offer the required interfaces.
The easiest way is to deploy COS Lite with the
[offers overlay](https://github.com/canonical/cos-lite-bundle/blob/main/overlays/offers-overlay.yaml),
which creates cross-model offers named `grafana-dashboards`, `loki-logging`, and
`prometheus-receive-remote-write`:

```shell
juju switch <k8s-controller>:<cos-model>
juju deploy cos-lite --trust \
    --overlay https://raw.githubusercontent.com/canonical/cos-lite-bundle/main/overlays/offers-overlay.yaml
```

If COS Lite is already deployed without the overlay, offer the interfaces manually:

```shell
juju offer grafana:grafana-dashboard
juju offer loki:logging
juju offer prometheus:receive-remote-write
```

## Consume offers from the OpenSearch model

Switch to the OpenSearch model and consume the COS offers:

```shell
juju switch <opensearch-controller>:<opensearch-model>
juju consume <k8s-controller>:admin/<cos-model>.grafana-dashboards
juju consume <k8s-controller>:admin/<cos-model>.loki-logging
juju consume <k8s-controller>:admin/<cos-model>.prometheus-receive-remote-write
```

## Deploy and integrate Grafana Agent

Deploy `grafana-agent` in the OpenSearch model:

```shell
juju deploy grafana-agent
```

Integrate it with the consumed COS offers:

```shell
juju integrate grafana-agent grafana-dashboards
juju integrate grafana-agent loki-logging
juju integrate grafana-agent prometheus-receive-remote-write
```

Integrate it with OpenSearch:

```shell
juju integrate grafana-agent opensearch:cos-agent
```

After integration, Grafana will display the **Charmed OpenSearch** dashboard
and Loki will receive OpenSearch logs.

### Large deployments

For multi-application clusters, integrate `grafana-agent` with each OpenSearch application.
The dashboard aggregates data from all connected units.

### Multiple clusters

Multiple deployments can share the same COS instance.
The dashboard provides selectors to filter by cluster.

## Access the Grafana web interface

Retrieve the Grafana admin password:

```shell
juju run grafana/leader get-admin-password --model <k8s-controller>:<cos-model>
```

For detailed instructions, see
[Browse dashboards](https://documentation.ubuntu.com/observability/track-3.0/tutorial/cos-lite-microk8s-sandbox/#browse-dashboards)
in the COS tutorial.

In Grafana, select the **Charmed OpenSearch** dashboard. You can filter by
application name, unit, model, cluster, and node roles.

```{note}
For exploring and visualising your indexed data (as opposed to cluster health metrics),
deploy [Charmed OpenSearch Dashboards](https://canonical-charmed-opensearch-dashboards.readthedocs-hosted.com/).
```

## Expected result

Grafana displays the **Charmed OpenSearch** dashboard with metrics from all OpenSearch units,
and Loki receives OpenSearch logs. Verify by checking the dashboard in Grafana and confirming
that metrics and logs appear for each unit.

## Next steps

* [Perform load testing](how-to-perform-load-testing) — benchmark the cluster under load with COS monitoring.
* [Monitoring explanation](explanation-monitoring) — background on monitoring features.
