# Terraform module for opensearch-operator

This is a Terraform module facilitating the deployment of the OpenSearch K8s charm with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs).

This module requires a `juju` Kubernetes model to be available. Refer to the [usage section](#usage) below for more details.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.6 |
| juju | ~> 2.0 |

## Providers

| Name | Version |
| ---- | ------- |
| juju | ~> 2.0 |
| terraform | n/a |

## Inputs

| Name | Description | Default | Required |
| ---- | ----------- | ------- | :------: |
| apps | Non-orchestrator OpenSearch apps. Defaults to one app with 'data' role. | <pre>[<br/>  {<br/>    "app_name": "data",<br/>    "config": {<br/>      "roles": "data"<br/>    }<br/>  }<br/>]</pre> | no |
| backups-integrator | Configuration for the optional backup integrator | `null` | no |
| certificates_integration | External TLS endpoint or offer. | `null` | no |
| cluster_name | The cluster name of the fleet. | `"opensearch"` | no |
| data-integrator | Configuration for the optional data-integrator | `null` | no |
| failover | Optional failover orchestrator | `null` | no |
| grafana_dashboard_integration | Optional COS Grafana dashboard endpoint or offer. | `null` | no |
| ingress_integration | External ingress endpoint or offer for OpenSearch Dashboards, used instead of the bundled traefik-k8s. | `null` | no |
| logging_integration | Optional COS logging endpoint or offer. | `null` | no |
| main | Main orchestrator app definition. Default role is cluster_manager. | n/a | yes |
| metrics_endpoint_integration | Optional COS metrics endpoint or offer. | `null` | no |
| opensearch-dashboards | Optional OpenSearch Dashboards app definition | `null` | no |
| self-signed-certificates | Configuration for the self-signed-certificates app | `{}` | no |
| traefik-k8s | Configuration for the traefik-k8s app. Deployed when OpenSearch Dashboards is deployed, unless ingress_integration is set | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| app_names | Output of all deployed application names. |
| metadata | Product deployment metadata. |
| models | Deployed applications |
| offers | List of offers URLs. |
| provides | Map of all 'provides' endpoints of the main orchestrator |
| requires | Map of all 'requires' endpoints of the main orchestrator |
<!-- END_TF_DOCS -->

## Usage

This module is intended to be a product module, deploying all components for a proper and large opensearch deployment on Kubernetes: a main orchestrator, an optional failover orchestrator and other OpenSearch apps, forming one cluster, optionally across several models.

It may be used as-is and directly as follows:
```
terraform plan \
  -var='main={"model_uuid": "<model-uuid>"}' \
  -var='failover={}' \
  -var='apps=[{"app_name": "data-hot", "config": {"roles": "data.hot"}}, {"app_name": "data-cold", "model_uuid": "<other-model-uuid>", "config": {"roles": "data.cold"}}]' \
  -var='backups-integrator={"config": {"bucket": "mybucket"}}' \
  -out terraform.out

terraform apply terraform.out
```

### Configure backups

To set credentials for the backups integrator, wait until it reaches `blocked` status and, for S3, run:

```shell
juju run s3-integrator/leader sync-s3-credentials \
    access-key=<access-key> \
    secret-key=<secret-key>
```

For Azure storage and GCS, set `backups-integrator.config.credentials` to a Juju secret URI and grant the secret to the integrator. See [How to back up and restore](https://canonical.com/data/opensearch/docs/latest/how-to/back-up-and-restore/).
