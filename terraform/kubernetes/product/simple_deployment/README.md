# Terraform module for opensearch-operator

This is a Terraform module facilitating the deployment of the OpenSearch K8s charm with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs).

## Requirements

| Name | Version |
|------|---------|
| `Terraform` | >= 1.6 |
| `Juju provider` | ~> 2.0 |

This module requires a `juju` Kubernetes model to be available. Refer to the [usage section](#usage) below for more details.

## Providers

| Name | Version |
| ---- | ------- |
| `juju` | ~> 2.0 |

## Module

| Name | Source | Version |
|------|--------|---------|
| `opensearch` | ../../charm/opensearch | n/a |
| `opensearch-dashboards` | git::https://github.com/canonical/opensearch-dashboards-operator.git//terraform/kubernetes/charm/opensearch_dashboards | 8b93e9fd8c686f6d4cf8617380d5d8c07c2d8786 |

## Resources

| Name | Type | Description |
|------|------|-------------|
| `juju_application.self-signed-certificates` | [Juju application](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | Deploys self-signed-certificates in the OpenSearch model, unless `certificates_integration` is set. |
| `juju_application.traefik-k8s` | [Juju application](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | Deploys traefik-k8s as the ingress for OpenSearch Dashboards, unless `ingress_integration` is set. |
| `juju_application.data-integrator` | [Juju application](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | Deploys the optional data-integrator application. |
| `juju_application.backups-integrator` | [Juju application](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | Deploys the optional S3, Azure storage or GCS integrator. |
| `juju_integration.opensearch-tls-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch to self-signed-certificates, or to the `certificates_integration` target. |
| `juju_integration.opensearch_dashboards-tls-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch Dashboards to the same TLS provider as OpenSearch if `opensearch-dashboards.tls` is set to `true`. |
| `juju_integration.opensearch_dashboards-opensearch-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch Dashboards to OpenSearch. |
| `juju_integration.opensearch_dashboards-ingress-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch Dashboards to traefik-k8s, or to the `ingress_integration` target. |
| `juju_integration.backups_integrator-opensearch-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch to the backups integrator, using an offer when cross-model. |
| `juju_integration.data_integrator-opensearch-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates data-integrator to OpenSearch, using an offer when cross-model. |
| `juju_integration.grafana_dashboard-opensearch-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch to the `grafana_dashboard_integration` target. |
| `juju_integration.grafana_dashboard-opensearch_dashboards-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch Dashboards to the `grafana_dashboard_integration` target. |
| `juju_integration.logging-opensearch-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch to the `logging_integration` target. |
| `juju_integration.logging-opensearch_dashboards-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch Dashboards to the `logging_integration` target. |
| `juju_integration.metrics_endpoint-opensearch-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch to the `metrics_endpoint_integration` target. |
| `juju_integration.metrics_endpoint-opensearch_dashboards-integration` | [Juju integration](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/integration) | Relates OpenSearch Dashboards to the `metrics_endpoint_integration` target. |
| `juju_offer.opensearch_client` | [Juju offer](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/offer) | Offers OpenSearch's `opensearch-client` endpoint for cross-model data-integrator relations. |
| `juju_offer.backups_credentials` | [Juju offer](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/offer) | Offers the backups integrator credentials endpoint for cross-model relations. |
| `terraform_data.deployed_at` | [Terraform data](https://developer.hashicorp.com/terraform/language/resources/terraform-data) | Stores the first deployment timestamp for product metadata. |
| `terraform_data.updated_at` | [Terraform data](https://developer.hashicorp.com/terraform/language/resources/terraform-data) | Stores the timestamp of the last change to the module's inputs. |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `opensearch` | OpenSearch app definition | <pre>object({<br/>  app_name           = optional(string, "opensearch-k8s")<br/>  model_uuid         = string<br/>  config             = optional(map(string), { "cluster_name" : "opensearch" })<br/>  channel            = optional(string, "2/edge")<br/>  base               = optional(string, "ubuntu@24.04")<br/>  revision           = optional(number)<br/>  units              = optional(number, 3)<br/>  constraints        = optional(string, "arch=amd64")<br/>  resources          = optional(map(string), {})<br/>  storage_directives = optional(map(string), {})<br/>  expose = optional(list(object({<br/>    cidrs     = optional(string)<br/>    endpoints = optional(string)<br/>    spaces    = optional(string)<br/>  })), [])<br/>})</pre> | n/a | yes |
| `opensearch-dashboards` | Optional OpenSearch Dashboards app definition. The charm needs an ingress, so traefik-k8s is deployed with it unless `ingress_integration` is set. | <pre>object({<br/>  app_name    = optional(string, "opensearch-dashboards-k8s")<br/>  config      = optional(map(string), {})<br/>  channel     = optional(string, "2/edge")<br/>  base        = optional(string, "ubuntu@24.04")<br/>  revision    = optional(number)<br/>  units       = optional(number, 1)<br/>  constraints = optional(string, "arch=amd64")<br/>  resources   = optional(map(string), {})<br/>  tls         = optional(bool, false)<br/>  expose = optional(list(object({<br/>    cidrs     = optional(string)<br/>    endpoints = optional(string)<br/>    spaces    = optional(string)<br/>  })), [])<br/>})</pre> | `null` | no |
| `traefik-k8s` | Configuration for the traefik-k8s app. Ignored when `ingress_integration` is set or OpenSearch Dashboards is not deployed. | <pre>object({<br/>  channel     = optional(string, "latest/stable")<br/>  revision    = optional(number)<br/>  base        = optional(string)<br/>  units       = optional(number, 1)<br/>  constraints = optional(string, "arch=amd64")<br/>  config      = optional(map(string), {})<br/>})</pre> | `{}` | no |
| `ingress_integration` | Optional external ingress provider for OpenSearch Dashboards, used instead of the bundled traefik-k8s. Use kind = "endpoint" with name/endpoint for integrations in the same model. Use kind = "offer" with url for cross-model integrations. `controller` can only be used with kind = "offer". | <pre>object({<br/>  kind       = string<br/>  name       = optional(string)<br/>  endpoint   = optional(string)<br/>  url        = optional(string)<br/>  controller = optional(string)<br/>})</pre> | `null` | no |
| `backups-integrator` | Optional configuration for the backup integrator. `storage_type` selects the S3, Azure storage or GCS integrator. When `model_uuid` is omitted, the integrator is deployed in the OpenSearch model. Cross-model relations use the integrator's Juju offer. When `channel` or `base` is omitted, S3 and Azure storage use `latest/edge` on `ubuntu@22.04`, and GCS uses `1/edge` on `ubuntu@24.04`. | <pre>object({<br/>  model_uuid   = optional(string)<br/>  storage_type = optional(string, "s3")<br/>  config       = optional(map(string), {})<br/>  channel      = optional(string)<br/>  base         = optional(string)<br/>  revision     = optional(number)<br/>  constraints  = optional(string, "arch=amd64")<br/>})</pre> | `null` | no |
| `data-integrator` | Optional configuration for the data-integrator. When `model_uuid` is omitted, the data-integrator is deployed in the OpenSearch model. Cross-model relations use OpenSearch's Juju offer. | <pre>object({<br/>  model_uuid  = optional(string)<br/>  config      = optional(map(string), { "index-name" : "test", "extra-user-roles" : "admin" })<br/>  channel     = optional(string, "latest/edge")<br/>  base        = optional(string, "ubuntu@22.04")<br/>  revision    = optional(number)<br/>  constraints = optional(string, "arch=amd64")<br/>})</pre> | `null` | no |
| `self-signed-certificates` | Configuration for the self-signed-certificates app. Ignored when `certificates_integration` is set. | <pre>object({<br/>  channel     = optional(string, "1/stable")<br/>  revision    = optional(number)<br/>  base        = optional(string, "ubuntu@24.04")<br/>  units       = optional(number, 1)<br/>  constraints = optional(string, "arch=amd64")<br/>  config      = optional(map(string), { "ca-common-name" : "CA" })<br/>})</pre> | `{}` | no |
| `certificates_integration` | Optional external TLS provider. Use kind = "endpoint" with name/endpoint for integrations in the same model. Use kind = "offer" with url for cross-model integrations. `controller` can only be used with kind = "offer". | <pre>object({<br/>  kind       = string<br/>  name       = optional(string)<br/>  endpoint   = optional(string)<br/>  url        = optional(string)<br/>  controller = optional(string)<br/>})</pre> | `null` | no |
| `grafana_dashboard_integration` | Optional COS Grafana dashboard provider, related to OpenSearch and OpenSearch Dashboards. Use kind = "endpoint" with name/endpoint for integrations in the same model. Use kind = "offer" with url for cross-model integrations. `controller` can only be used with kind = "offer". | <pre>object({<br/>  kind       = string<br/>  name       = optional(string)<br/>  endpoint   = optional(string)<br/>  url        = optional(string)<br/>  controller = optional(string)<br/>})</pre> | `null` | no |
| `logging_integration` | Optional COS logging provider, related to OpenSearch and OpenSearch Dashboards. Use kind = "endpoint" with name/endpoint for integrations in the same model. Use kind = "offer" with url for cross-model integrations. `controller` can only be used with kind = "offer". | <pre>object({<br/>  kind       = string<br/>  name       = optional(string)<br/>  endpoint   = optional(string)<br/>  url        = optional(string)<br/>  controller = optional(string)<br/>})</pre> | `null` | no |
| `metrics_endpoint_integration` | Optional COS metrics scraper, related to OpenSearch and OpenSearch Dashboards. Use kind = "endpoint" with name/endpoint for integrations in the same model. Use kind = "offer" with url for cross-model integrations. `controller` can only be used with kind = "offer". | <pre>object({<br/>  kind       = string<br/>  name       = optional(string)<br/>  endpoint   = optional(string)<br/>  url        = optional(string)<br/>  controller = optional(string)<br/>})</pre> | `null` | no |

## Outputs

| Name | Description |
|------|-------------|
| `app_names` | Map of deployed application names. |
| `metadata` | Metadata of the product deployment: `deployed_at`, the first deployment timestamp, and `updated_at`, the timestamp of the last change to the module's inputs. |
| `models` | Models and deployed components managed by this module. |
| `offers` | Cross-model offer URLs created by this module. |
| `provides` | OpenSearch provided endpoint pointers, including `opensearch_client`, `opensearch_grafana_dashboard` and `opensearch_metrics_endpoint`. |
| `requires` | OpenSearch required endpoint pointers, including certificates, backups credentials and logging endpoints. |

## Usage

This module is intended to be a product module, deploying all components for a proper yet simple opensearch deployment on Kubernetes.

It may be used as-is and directly as follows:
```
terraform plan \
  -var='opensearch={"model_uuid": "<model-uuid>"}' \
  -var='backups-integrator={"config": {"bucket": "mybucket"}}' \
  -out terraform.out

terraform apply terraform.out
```
