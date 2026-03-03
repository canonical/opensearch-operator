---
myst:
  html_meta:
    description: "Enable monitoring for Charmed OpenSearch by integrating with COS Lite bundle, Grafana, Loki, and Prometheus."
---

(how-to-monitoring)=
# Enable monitoring

This guide shows how to enable monitoring using Canonical Observability Stack (COS).

The OpenSearch charm uses COS to connect to Grafana and Prometheus to use monitoring,
alert rules, and log features.

```{note}
For exploring and visualizing your indexed data, deploy
[Charmed OpenSearch Dashboards](https://canonical-charmed-opensearch-dashboards.readthedocs-hosted.com/).
While COS monitors infrastructure health, OpenSearch Dashboards provides tools for data exploration
and custom visualizations.
```

For explanation of monitoring features, see the [Monitoring](explanation-monitoring)
explanation page.

Prerequisites:

* A deployed [Charmed OpenSearch operator](tutorial-2-deploy-opensearch)
* A deployed [`cos-lite` bundle in a Kubernetes environment](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s)

## Offer interfaces via the COS controller

First, switch to the COS K8s environment and offer COS interfaces to be cross-model
integrated with the Charmed OpenSearch model.

To switch to the Kubernetes controller for the COS model:

```shell
juju switch <k8s_cos_controller>:<cos_model_name>
```

To offer the COS interfaces:

```shell
juju offer grafana:grafana-dashboard
juju offer loki:logging
juju offer prometheus:receive-remote-write
```

## Consume offers via the OpenSearch model

Next, switch to the Charmed OpenSearch model, find offers, and consume them.

We are currently on the Kubernetes controller for the COS model.
To switch to the OpenSearch model:

```shell
juju switch <db_controller>:<opensearch_model_name>
```

To consume offers to be reachable in the current model:

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

Then, integrate (previously known as "[relate](https://documentation.ubuntu.com/juju/3.6/reference/relation/)")
it with Charmed OpenSearch:

```shell
juju integrate grafana-agent grafana
juju integrate grafana-agent loki
juju integrate grafana-agent prometheus
```

Finally, integrate `grafana-agent` with consumed COS offers:

```shell
juju integrate grafana-agent opensearch:grafana-dashboard
juju integrate grafana-agent opensearch:logging
juju integrate grafana-agent opensearch:cos-agent
```

After this is complete, Grafana will show the new dashboard `Charmed OpenSearch`
and will allow access to Charmed OpenSearch logs on Loki.

### Extend to Large Deployments

Large deployments run across multiple Juju applications.
Connect all the units of each application to grafana-agent, as explained above,
and the dashboard will be able to summarize the entire cluster.

### Connect Multiple Clusters

It is possible to have the same COS and dashboard for multiple deployments.
The dashboard provides selectors to filter which cluster to watch at the time.

## Connect to the Grafana web interface

To connect to the Grafana web interface, follow the
[Browse dashboards](https://charmhub.io/topics/canonical-observability-stack/tutorials/install-microk8s#heading--browse-dashboards)
section of the MicroK8s "Getting started" guide:

```shell
juju run grafana/leader get-admin-password --model <k8s_cos_controller>:<cos_model_name>
```

### Dashboard details

After accessing Grafana web interface, select the “Charmed OpenSearch” dashboard.

The dashboard filters for Juju-specific elements, e.g. application name, unit, model;
and also OpenSearch’s cluster and roles.
The cluster dropdown lets you choose which cluster’s statistics to display.
You can also filter the view by selecting specific node roles, including nodes that span different models or applications.

![Charmed-Opensearch Dashboard 1|690x342](img/dash1.png)

![Charmed-Opensearch Dashboard 2|690x324](img/dash2.png)

![Charmed-Opensearch Dashboard 3|690x336](img/cos-1.png)

## OpenSearch Dashboards for data visualization and exploration

While COS and Grafana provide excellent infrastructure monitoring, metrics, and alerting capabilities focused on the health of your OpenSearch cluster, OpenSearch Dashboards is designed for exploring and visualizing the actual data stored in your indices.

**OpenSearch Dashboards provides:**

* **Interactive data exploration** - Query and filter your indexed data with an intuitive interface
* **Custom visualizations** - Create charts, graphs, maps, and other visual representations of your data
* **Dashboard builder** - Combine multiple visualizations into comprehensive, interactive dashboards
* **Index management** - View, create, and manage your indices and index patterns
* **{spellexception}`Dev` Tools** - Run queries and explore your data using the integrated console
* **Advanced features** - Access OpenSearch-specific capabilities like anomaly detection, alerting, and more

**Grafana vs. OpenSearch Dashboards:**

* **Grafana** (via COS) - Best for monitoring cluster health, performance metrics, resource usage, and operational alerts
* **OpenSearch Dashboards** - Best for exploring your business/application data, creating custom analytics, and building user-facing dashboards

For most production deployments, you'll want both: COS/Grafana for operational monitoring and OpenSearch Dashboards for data analytics and visualization.

To get started with OpenSearch Dashboards, see the [Charmed OpenSearch Dashboards documentation](https://canonical-charmed-opensearch-dashboards.readthedocs-hosted.com/).


