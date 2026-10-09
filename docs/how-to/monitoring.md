---
myst:
  html_meta:
    description: Enable monitoring for Charmed OpenSearch on VMs or Kubernetes by integrating with COS Lite bundle, Grafana, Loki, and Prometheus.
---

(how-to-monitoring)=

# How to enable monitoring (COS)

This guide shows how to integrate Charmed OpenSearch with the Canonical Observability Stack (COS) for metrics,
dashboards, alerts, and logs.

The integration workflow depends on the charm variant:

- On **VMs**, the `opensearch` machine charm exposes a single `cos-agent` endpoint, and a machine `grafana-agent` charm
  collects and forwards the telemetry to COS.
- On **Kubernetes**, the `opensearch-k8s` charm exposes native COS endpoints (`metrics-endpoint`, `grafana-dashboard`,
  and `logging`), and a `grafana-agent-k8s` charm in the OpenSearch model collects and forwards the telemetry to COS. If
  COS Lite runs in the same model, OpenSearch can integrate with the COS applications directly instead.

For background on monitoring features, see the [Monitoring explanation](explanation-monitoring).

## Prerequisites

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

* A deployed [Charmed OpenSearch cluster](tutorial-2-deploy-opensearch)
* A deployed [`cos-lite` bundle in a Kubernetes environment](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s),
  in a model separate from the OpenSearch model
````

````{tab-item} K8s
:sync: k8s

* A deployed [`opensearch-k8s`](https://charmhub.io/opensearch-k8s) application with TLS configured
* A deployed [`cos-lite` bundle](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s),
  either in the same Kubernetes model as `opensearch-k8s` or in a separate model

```{tip}
The COS documentation recommends a dedicated model for COS Lite.
If you deploy COS Lite in the OpenSearch model instead (`juju deploy cos-lite --trust`),
skip the offer and consume steps below and [integrate the applications directly](integrate-with-cos).
```
````
`````

## Offer COS interfaces

Switch to the COS K8s controller and offer the required interfaces. The easiest way is to deploy COS Lite with the
[offers overlay](https://github.com/canonical/cos-lite-bundle/blob/main/overlays/offers-overlay.yaml), which creates
cross-model offers named `grafana-dashboards`, `loki-logging`, and `prometheus-receive-remote-write`:

```shell
juju switch <k8s-controller>:<cos-model>
curl -L https://raw.githubusercontent.com/canonical/cos-lite-bundle/main/overlays/offers-overlay.yaml -O
juju deploy cos-lite --trust --overlay ./offers-overlay.yaml
```

If COS Lite is already deployed without the overlay, offer the interfaces manually:

```shell
juju offer grafana:grafana-dashboard grafana-dashboards
juju offer loki:logging loki-logging
juju offer prometheus:receive-remote-write prometheus-receive-remote-write
```

## Consume offers from the OpenSearch model

Switch to the OpenSearch model and consume the COS offers:

```shell
juju switch <opensearch-controller>:<opensearch-model>
juju consume <k8s-controller>:admin/<cos-model>.grafana-dashboards
juju consume <k8s-controller>:admin/<cos-model>.loki-logging
juju consume <k8s-controller>:admin/<cos-model>.prometheus-receive-remote-write
```

(integrate-with-cos)=

## Integrate with COS

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

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
````

````{tab-item} K8s
:sync: k8s

Deploy [`grafana-agent-k8s`](https://charmhub.io/grafana-agent-k8s) in the OpenSearch model:

```shell
juju deploy grafana-agent-k8s --trust
```

Integrate it with the consumed COS offers:

```shell
juju integrate grafana-agent-k8s:grafana-dashboards-provider grafana-dashboards
juju integrate grafana-agent-k8s:logging-consumer loki-logging
juju integrate grafana-agent-k8s:send-remote-write prometheus-receive-remote-write
```

Integrate it with OpenSearch:

```shell
juju integrate opensearch-k8s:metrics-endpoint grafana-agent-k8s:metrics-endpoint
juju integrate opensearch-k8s:grafana-dashboard grafana-agent-k8s:grafana-dashboards-consumer
juju integrate opensearch-k8s:logging grafana-agent-k8s:logging-provider
```

* `metrics-endpoint` lets the agent scrape the OpenSearch metrics endpoint.
* `grafana-dashboard` transfers the **Charmed OpenSearch** dashboard.
* `logging` sends the OpenSearch logs.

If COS Lite is deployed in the **same model** as `opensearch-k8s`, skip the agent
and the offers, and integrate OpenSearch with the COS applications directly:

```shell
juju integrate opensearch-k8s:metrics-endpoint prometheus:metrics-endpoint
juju integrate opensearch-k8s:grafana-dashboard grafana:grafana-dashboard
juju integrate opensearch-k8s:logging loki:logging
```
````
`````

After integration, Grafana will display the **Charmed OpenSearch** dashboard and Loki will receive OpenSearch logs.

### Large deployments

`````{tab-set}
---
sync-group: substrate
---
````{tab-item} VM
:sync: vm

For multi-application clusters, integrate `grafana-agent` with each OpenSearch application.
The dashboard aggregates data from all connected units.
````

````{tab-item} K8s
:sync: k8s

For multi-application clusters, repeat the three OpenSearch integrations
(`metrics-endpoint`, `grafana-dashboard`, and `logging`) for each OpenSearch application.
The dashboard aggregates data from all connected units.
````
`````

### Multiple clusters

Multiple deployments can share the same COS instance. The dashboard provides selectors to filter by cluster.

## Access the Grafana web interface

Retrieve the Grafana admin password:

```shell
juju run grafana/leader get-admin-password --model <k8s-controller>:<cos-model>
```

For detailed instructions, see
[Browse dashboards](https://documentation.ubuntu.com/observability/track-3.0/tutorial/cos-lite-microk8s-sandbox/#browse-dashboards)
in the COS tutorial.

In Grafana, select the **Charmed OpenSearch** dashboard. You can filter by Juju model, application, unit, cluster, and
node role.

![Charmed OpenSearch Grafana dashboard showing cluster health and shard counts](img/dash1.png)

![Charmed OpenSearch Grafana dashboard showing system usage and indexing metrics](img/dash2.png)

To inspect OpenSearch logs, open **Explore** in Grafana, select the Loki data source, filter by `juju_application`, and
run the query:

![Grafana Explore showing OpenSearch logs filtered by Juju application](img/cos-1.png)

```{note}
For exploring and visualising your indexed data (as opposed to cluster health metrics),
deploy [Charmed OpenSearch Dashboards](https://canonical-charmed-opensearch-dashboards.readthedocs-hosted.com/).
```

## Next steps

- [Perform load testing](how-to-perform-load-testing) — benchmark the cluster under load with COS monitoring.
- [Monitoring explanation](explanation-monitoring) — background on monitoring features.
