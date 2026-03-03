(explanation-monitoring)=
# Monitoring

The OpenSearch charm integrates with the Canonical Observability Stack (COS)
to provide infrastructure and cluster health monitoring through metrics, dashboards, alert rules, and logs.
COS uses Prometheus for metrics collection, Grafana for visualization, Loki for log aggregation,
and Alertmanager for alerting. This enables monitoring of OpenSearch cluster performance,
resource utilization (CPU, memory, disk I/O), cluster statistics (node health, shard allocation, indexing rates),
and operational health.

```{note}
See: [How to enable monitoring](how-to-monitoring) via COS and Grafana.
```

Additionally, Charmed OpenSearch can integrate with the [OpenSearch Dashboards](https://canonical-charmed-opensearch-dashboards.readthedocs-hosted.com/2/) charm
for exploring and visualizing your indexed business or application data.
While COS with Grafana monitors your OpenSearch infrastructure and operational health,
OpenSearch Dashboards provides purpose-built tools for interactive data exploration,
custom visualizations, query builders, and OpenSearch-specific features like anomaly detection.
Most production deployments benefit from using both: COS for infrastructure monitoring
and OpenSearch Dashboards for data analysis.

```{note}
See: [How to deploy OpenSearch Dashboards](https://canonical-charmed-opensearch-dashboards.readthedocs-hosted.com/2/how-to/deploy/) charm.
```

## Metrics

The charm enables the Prometheus Exporter plugin for OpenSearch by default:
[The Prometheus Exporter Plugin for OpenSearch](https://github.com/Aiven-Open/prometheus-exporter-plugin-for-opensearch)

The meaning of the metrics collected can be found in the upstream documentation:

* [{spellexception}`indices_stats_metrics`](https://opensearch.org/docs/latest/api-reference/index-apis/stats/)
* [{spellexception}`nodes_stats_metrics`](https://opensearch.org/docs/latest/api-reference/nodes-apis/nodes-stats/)
* [{spellexception}`cluster_stats_metrics`](https://opensearch.org/docs/latest/api-reference/cluster-api/cluster-stats/)

## Alert rules

The charm deploys a pre-configured set of Prometheus alert rules by default.

To ensure you are referencing the latest default alert rules, check the source file of alert definitions in the repository’s [prometheus_alerts.yaml](https://github.com/canonical/opensearch-operator/blob/2/edge/src/alert_rules/prometheus/prometheus_alerts.yaml) file.

## Logs

All the logs from the OpenSearch payload are available in the Grafana GUI at `Home > Explore`

To get OpenSearch logs, go to the `Label filters` field and set to `juju_application = opensearch`, select one operation, e.g. `Line contains` and run the query.
