# OpenSearch Kubernetes product module

This is a Terraform module facilitating the deployment of the OpenSearch K8s charm with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs).

Pass the UUID of an existing Kubernetes model as `opensearch.model_uuid`. All apps are deployed in that model.

## Deployed stack

- OpenSearch, 3 units by default, in an existing model.
- `self-signed-certificates`, unless `certificates_integration` is set.
- Optional: OpenSearch Dashboards (`opensearch_dashboards`, needs `ingress_integration`), `data-integrator` (`data_integrator`), a backup integrator (`backups`, or an existing one through `backups_integration`).
- Optional: COS through `metrics_endpoint_integration`, `logging_integration` and `grafana_dashboard_integration`.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.11 |
| juju | ~> 2.2 |

## Inputs

| Name | Description | Default | Required |
| ---- | ----------- | ------- | :------: |
| azure_storage_secret_key | Azure Storage account key for `azure-storage-integrator`. Supply through `TF_VAR_azure_storage_secret_key` or `-var`, at plan and at apply. | `null` | no |
| azure_storage_secret_version | Version of the `azure-storage-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove. | `0` | no |
| backups | Configuration for the optional backup integrator. | `null` | no |
| backups_integration | External backup storage endpoint or offer. | `null` | no |
| certificates_integration | External TLS endpoint or offer. | `null` | no |
| data_integrator | Configuration for the optional `data-integrator`. | `null` | no |
| gcs_secret_key | GCS service-account JSON key for `gcs-integrator`. Supply through `TF_VAR_gcs_secret_key` or `-var`, at plan and at apply. | `null` | no |
| gcs_secret_version | Version of the `gcs-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove. | `0` | no |
| grafana_dashboard_integration | Optional COS Grafana dashboard endpoint or offer. | `null` | no |
| ingress_integration | Ingress endpoint or offer for OpenSearch Dashboards. Required when Dashboards is deployed. | `null` | no |
| logging_integration | Optional COS logging endpoint or offer. | `null` | no |
| metrics_endpoint_integration | Optional COS metrics endpoint or offer. | `null` | no |
| offered_endpoints | OpenSearch endpoints to expose as Juju offers. | `[]` | no |
| opensearch | OpenSearch app definition. | n/a | yes |
| opensearch_dashboards | Optional OpenSearch Dashboards app definition. | `null` | no |
| s3_access_key | S3 access key for `s3-integrator`. Supply through `TF_VAR_s3_access_key` or `-var`, at plan and at apply. | `null` | no |
| s3_secret_key | S3 secret key for `s3-integrator`. Supply through `TF_VAR_s3_secret_key` or `-var`, at plan and at apply. | `null` | no |
| s3_secret_version | Version of the `s3-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove. | `0` | no |
| self_signed_certificates | Configuration for the `self-signed-certificates` app. | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| app_names | Names of the deployed apps. |
| metadata | Product deployment metadata. |
| models | The model and the apps deployed in it. |
| offers | Map of offer URLs. |
| provides | Map of all `provides` endpoints. |
| requires | Map of all `requires` endpoints. |
<!-- END_TF_DOCS -->

## Usage

### Basic deployment

```hcl
module "opensearch" {
  source = "git::https://github.com/canonical/opensearch-operator//terraform/kubernetes/product/simple_deployment?ref=<commit>"

  opensearch = { model_uuid = juju_model.opensearch.uuid }
}
```

### Backups

To deploy a backup integrator with the module, set `backups` with the storage type (`s3`, `azure-storage` or `gcs`) and its settings.

```hcl
backups = {
  storage_type = "s3"
  config       = { bucket = "my-bucket", path = "opensearch", region = "eu-central-1" }
}
s3_access_key     = var.s3_access_key
s3_secret_key     = var.s3_secret_key
s3_secret_version = 1
```

Supply credentials through environment variables or command-line flags at plan and apply. The module stores them in a Juju secret through the provider's write-only `value_wo`, so they aren't stored in the Terraform state.

```shell
export TF_VAR_s3_access_key="..."
export TF_VAR_s3_secret_key="..."
```

The `s3_secret_version` variable controls the secret: `0` none, `1` create, increment to rotate, back to `0` to remove.

For Azure Storage, use `azure_storage_secret_key` and `azure_storage_secret_version`. For GCS, use `gcs_secret_key` and `gcs_secret_version`.

Alternatively, set `backups.credentials_secret_uri` to a Juju secret you created and granted to the integrator. The secret version must then be `0`.

To use your own integrator, set `backups_integration` instead of `backups`:

```hcl
backups_integration = { storage_type = "s3", kind = "offer", url = "admin/storage.s3-integrator" }
```

### COS

The module doesn't deploy COS. To enable monitoring, deploy a collector, such as `opentelemetry-collector-k8s`, in the same model, relate it to COS, and pass its endpoints. OpenSearch and Dashboards then send metrics, logs and dashboards through it.

```hcl
metrics_endpoint_integration  = { kind = "endpoint", name = "opentelemetry-collector-k8s", endpoint = "metrics-endpoint" }
logging_integration           = { kind = "endpoint", name = "opentelemetry-collector-k8s", endpoint = "receive-loki-logs" }
grafana_dashboard_integration = { kind = "endpoint", name = "opentelemetry-collector-k8s", endpoint = "grafana-dashboards-consumer" }
```

### Ingress for OpenSearch Dashboards

On Kubernetes, OpenSearch Dashboards is reached through an ingress, so the module requires one when Dashboards is deployed. Deploy an ingress provider, such as `traefik-k8s` and pass its `ingress` endpoint:

```hcl
opensearch_dashboards = {}
ingress_integration   = { kind = "endpoint", name = "traefik-k8s", endpoint = "ingress" }
```

Set `opensearch_dashboards.tls = true` to give Dashboards its own certificate from the TLS provider. Dashboards then serves `https` to the ingress provider.

### TLS

The module requires a TLS provider. By default, it deploys `self-signed-certificates`. To use your own provider, set `certificates_integration`:

```hcl
certificates_integration = { kind = "offer", url = "admin/pki.vault" }
```
