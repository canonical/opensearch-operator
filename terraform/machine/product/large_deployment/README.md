# OpenSearch machine large deployment product module

This is a Terraform module facilitating the deployment of the OpenSearch charm as one cluster made from multiple OpenSearch apps, with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs).

Pass the UUID of an existing machine model as `main.model_uuid`. Supporting apps are deployed in the same model. Other OpenSearch apps can be deployed in other models.

## Deployed stack

- OpenSearch `main`, the main orchestrator, 3 units with the `cluster_manager` role by default, in an existing model.
- Optional: OpenSearch `failover`, the failover orchestrator, 3 units with the `cluster_manager` role by default (`failover`).
- Other OpenSearch apps (`apps`), 3 units each. By default, one app `data` with the `data` role.
- `self-signed-certificates` and an offer of its `certificates` endpoint, unless `certificates_integration` is set.
- Optional: OpenSearch Dashboards (`opensearch_dashboards`), `data-integrator` (`data_integrator`), a backup integrator (`backups`, or an existing one through `backups_integration`).
- Optional: COS integration with an existing collector in `main`'s model. Apps in other models integrate via `cos_collector` with a collector in their own model.

All OpenSearch apps join one cluster named `cluster_name` (`opensearch` by default).

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.11 |
| juju | ~> 2.2 |

## Inputs

| Name | Description | Default | Required |
| ---- | ----------- | ------- | :------: |
| apps | Non-orchestrator OpenSearch apps. Defaults to one `data` app. | <pre>[<br/>  {<br/>    "app_name": "data",<br/>    "config": {<br/>      "roles": "data"<br/>    }<br/>  }<br/>]</pre> | no |
| azure_storage_secret_key | Azure Storage account key for `azure-storage-integrator`. Supply through `TF_VAR_azure_storage_secret_key` or `-var`, at plan and at apply. | `null` | no |
| azure_storage_secret_version | Version of the `azure-storage-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove. | `0` | no |
| backups | Configuration for the optional backup integrator. | `null` | no |
| backups_integration | External backup storage endpoint or offer. | `null` | no |
| certificates_integration | External TLS endpoint or offer. | `null` | no |
| cluster_name | Cluster name for all OpenSearch apps. | `"opensearch"` | no |
| cos_agent_integration | COS agent endpoint. | `null` | no |
| data_integrator | Configuration for the optional `data-integrator`. | `null` | no |
| failover | Optional failover orchestrator app definition. | `null` | no |
| gcs_secret_key | GCS service-account JSON key for `gcs-integrator`. Supply through `TF_VAR_gcs_secret_key` or `-var`, at plan and at apply. | `null` | no |
| gcs_secret_version | Version of the `gcs-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove. | `0` | no |
| main | Main orchestrator app definition. | n/a | yes |
| offered_endpoints | OpenSearch endpoints to expose as Juju offers. | `[]` | no |
| opensearch_dashboards | Optional OpenSearch Dashboards app definition. | `null` | no |
| s3_access_key | S3 access key for `s3-integrator`. Supply through `TF_VAR_s3_access_key` or `-var`, at plan and at apply. | `null` | no |
| s3_secret_key | S3 secret key for `s3-integrator`. Supply through `TF_VAR_s3_secret_key` or `-var`, at plan and at apply. | `null` | no |
| s3_secret_version | Version of the `s3-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove. | `0` | no |
| self_signed_certificates | Configuration for the `self-signed-certificates` app. | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| app_names | Output of all deployed application names. |
| metadata | Product deployment metadata. |
| models | Deployed applications. |
| offers | Map of offer URLs. |
| provides | Map of all `provides` endpoints of the main orchestrator. |
| requires | Map of all `requires` endpoints of the main orchestrator. |
<!-- END_TF_DOCS -->

## Usage

### Basic deployment

```hcl
module "opensearch" {
  source = "git::https://github.com/canonical/opensearch-operator//terraform/machine/product/large_deployment?ref=<commit>"

  main = { model_uuid = juju_model.opensearch.uuid }
}
```

This deploys a `main` application with the `cluster_manager` role and a `data` application with the `data` role, defaulting to 3 units each.

### OpenSearch Apps and Roles

App names must be unique across `main`, `failover` and `apps`. To change the cluster name, set `cluster_name`.

App roles can be set with `config.roles`. At least one app must have a `data` role, such as `data`, `data.hot` or `data.cold`. If you set roles on `main` or `failover`, you must include the `cluster_manager` role.

```hcl
main     = { model_uuid = juju_model.opensearch.uuid }
failover = {}
apps = [
  { app_name = "data-hot", config = { roles = "data.hot" } },
]
```

### Backups

To deploy a backup integrator with the module, set `backups` with the storage type (`s3`, `azure-storage` or `gcs`) and its settings. The integrator is deployed in `main`'s model and integrates with `main`.

```hcl
backups = {
  storage_type = "s3"
  config       = { bucket = "my-bucket", path = "opensearch", region = "eu-central-1" }
}
s3_access_key     = var.s3_access_key
s3_secret_key     = var.s3_secret_key
s3_secret_version = 1
```

Supply credentials through environment variables or command-line flags at plan and apply. The module stores them in a Juju secret and not in the Terraform state.

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

The module doesn't deploy COS. To enable monitoring, deploy a collector, such as `opentelemetry-collector`, in `main`'s model, relate it to COS, and pass its `cos-agent` endpoint. All OpenSearch apps and Dashboards then send metrics, logs and dashboards through it.

```hcl
cos_agent_integration = { name = "opentelemetry-collector", endpoint = "cos-agent" }
```

To monitor apps in another model, deploy another collector there and set the app's `cos_collector` to the collector's name:

```hcl
apps = [
  {
    app_name      = "data"
    model_uuid    = juju_model.opensearch_data.uuid
    config        = { roles = "data" }
    cos_collector = "opentelemetry-collector"
  },
]
```

### OpenSearch Dashboards

```hcl
opensearch_dashboards = {}
```

Dashboards is deployed in `main`'s model and connects to `main`.

Set `opensearch_dashboards.tls = true` to give Dashboards its own certificate from the TLS provider. Dashboards then serves `https`.

### TLS

The module requires a TLS provider. By default, it deploys `self-signed-certificates`. To use your own provider, set `certificates_integration`:

```hcl
certificates_integration = { kind = "offer", url = "admin/pki.vault" }
```
