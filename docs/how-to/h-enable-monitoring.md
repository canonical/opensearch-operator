# How to enable monitoring (COS)

[note]All commands are written for juju >= v.3.1.7 [/note]

## Prerequisites

* A deployed [Charmed OpenSearch operator](/t/9716)
* A deployed [`cos-lite` bundle in a Kubernetes environment](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s)

## Summary

* [Offer interfaces via the COS controller](#offer-interfaces-via-the-cos-controller)
* [Consume offers via the OpenSearch model](#consume-offers-via-the-opensearch-model)
* [Deploy and integrate Grafana](#deploy-and-integrate-grafana)
* [Connect to the Grafana web interface](#connect-to-the-grafana-web-interface)
---

## Offer interfaces via the COS controller

First, we will switch to the COS K8s environment and offer COS interfaces to be cross-model integrated with the Charmed OpenSearch model.

To switch to the Kubernetes controller for the COS model, run

```shell
juju switch <k8s_cos_controller>:<cos_model_name>
```

To offer the COS interfaces, run

```shell
juju offer grafana:grafana-dashboard

juju offer loki:logging

juju offer prometheus:receive-remote-write
```

## Consume offers via the OpenSearch model

Next, we will switch to the Charmed OpenSearch model, find offers, and consume them.

We are currently on the Kubernetes controller for the COS model. To switch to the OpenSearch model, run

```shell
juju switch <db_controller>:<opensearch_model_name>
```

To consume offers to be reachable in the current model, run

```shell
juju consume <k8s_cos_controller>:admin/cos.grafana

juju consume <k8s_cos_controller>:admin/cos.loki

juju consume <k8s_cos_controller>:admin/cos.prometheus
```

## Deploy and integrate Grafana

First, deploy [grafana-agent](https://charmhub.io/grafana-agent):

```shell
juju deploy grafana-agent
```

Then, integrate (previously known as "[relate](https://juju.is/docs/juju/integration)") it with Charmed OpenSearch:

```shell
juju integrate grafana-agent grafana

juju integrate grafana-agent loki

juju integrate grafana-agent prometheus
```

Finally, integrate `grafana-agent` with consumed COS offers:

```shell
juju integrate grafana-agent-k8s opensearch:grafana-dashboard

juju integrate grafana-agent-k8s opensearch:logging

juju integrate grafana-agent-k8s opensearch:metrics-endpoint
```

After this is complete, Grafana will show the new dashboard `Charmed OpenSearch` and will allow access to Charmed OpenSearch logs on Loki.

### Extend to Large Deployments

Large deployments run across multiple juju applications. Connect all the units of each application to grafana-agent, as explained above, and the dashboard will be able to summarize the entire cluster.

### Connect Multiple Clusters

It is possible to have the same COS and dashboard for multiple deployments. The dashboard provides selectors to filter which cluster to watch at the time.

## Connect to the Grafana web interface

To connect to the Grafana web interface, follow the [Browse dashboards](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s?_ga=2.201254254.1948444620.1704703837-757109492.1701777558#heading--browse-dashboards) section of the MicroK8s "Getting started" guide.

```shell
juju run grafana/leader get-admin-password --model <k8s_cos_controller>:<cos_model_name>
```

### Dashboard details

After accessing Grafana web interface, select the “Charmed OpenSearch” dashboard:

![|624x249](https://lh7-us.googleusercontent.com/docsz/AD_4nXe4o8wsL34B2pxkwT3xSbWFVOzW8u7mnE1hWcrPhlyVwykM9Orr7VjX3GCuK1amj9gI3DXbXc2ktkABPUqwDY88ctOY4TlCbhOSEhjEflxThWuVrv1dw-hvMT509dh8pmjsVtx9gphzxsflhPV3ejcS1QGl?key=Vg-Dy5s3l8MJTtpFjpDLtQ)

The dashboard filters for juju-specific elements, e.g. application name, unit, model; and also OpenSearch’s cluster and roles. The cluster dropdown allows to select which cluster we want to see the statistics from:

![|624x88](https://lh7-us.googleusercontent.com/docsz/AD_4nXffMwk0RgsG8yKgnxoftbEsu8yUJu22_OMZMF0W_VmWbvO7sNZKlOJhuKBz1Mu-w9HG6gwI4bLEPO8gpPJ5lVSS1JG53n0oqgZ4NF3M6x80I-6VA6uYGf7vHtL7jd2I5CD4GeSb9yoAQECd3xemptgxEK8?key=Vg-Dy5s3l8MJTtpFjpDLtQ)

It is also possible to select a subset of nodes following roles. That can select nodes across models or applications as well.


![Screenshot from 2024-06-28 18-53-33|690x124](upload://6VrppOeXntY5zUga6LzBIo8umbB.png)