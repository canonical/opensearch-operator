# OpenSearch machine product module

Terraform product module that deploys OpenSearch on machines, with optional OpenSearch Dashboards, data-integrator, backups and COS. It follows the CC008 Charm Terraform Standards.

Pass the UUID of an existing machine model as `opensearch.model_uuid`. All apps are deployed in that model.

## Deployed stack

- OpenSearch, 3 units by default, in an existing model.
- `self-signed-certificates`, unless `certificates_integration` is set.
- Optional: OpenSearch Dashboards (`opensearch_dashboards`), `data-integrator` (`data_integrator`), a backup integrator (`backups`, or an existing one through `backups_integration`).
- Optional: COS through an existing `cos-agent` provider (`cos_agent_integration`).

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.11 |
| juju | >= 2.2.1 |

## Inputs

| Name | Description | Default | Required |
| ---- | ----------- | ------- | :------: |
| azure_storage_secret_key | Azure Storage account key for `azure-storage-integrator`. Supply through `TF_VAR_azure_storage_secret_key`, at plan and at apply. | `null` | no |
| azure_storage_secret_uri | URI of an existing Juju secret holding the Azure Storage account key. | `null` | no |
| azure_storage_secret_version | Version of the `azure-storage-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove. | `0` | no |
| backups | Configuration for the optional backup integrator. | `null` | no |
| backups_integration | External backup storage endpoint or offer. | `null` | no |
| certificates_integration | External TLS endpoint or offer. | `null` | no |
| cos_agent_integration | COS agent endpoint. | `null` | no |
| data_integrator | Configuration for the optional `data-integrator`. | `null` | no |
| gcs_secret_key | GCS service-account JSON key for `gcs-integrator`. Supply through `TF_VAR_gcs_secret_key`, at plan and at apply. | `null` | no |
| gcs_secret_uri | URI of an existing Juju secret holding the GCS key. | `null` | no |
| gcs_secret_version | Version of the `gcs-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove. | `0` | no |
| offered_endpoints | OpenSearch endpoints to expose as Juju offers. | `[]` | no |
| opensearch | OpenSearch app definition. | n/a | yes |
| opensearch_dashboards | Optional OpenSearch Dashboards app definition. | `null` | no |
| s3_access_key | S3 access key for `s3-integrator`. Supply through `TF_VAR_s3_access_key`, at plan and at apply. | `null` | no |
| s3_secret_key | S3 secret key for `s3-integrator`. Supply through `TF_VAR_s3_secret_key`, at plan and at apply. | `null` | no |
| s3_secret_uri | URI of an existing Juju secret holding the S3 keys. | `null` | no |
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
  source = "git::https://github.com/canonical/opensearch-operator//terraform/machine/product/simple_deployment?ref=<commit>"

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

Alternatively, set `s3_secret_uri`, `gcs_secret_uri` or `azure_storage_secret_uri` to a Juju secret you created. The secret version must then be `0`.

To use your own integrator, set `backups_integration` instead of `backups`:

```hcl
backups_integration = { storage_type = "s3", kind = "offer", url = "admin/storage.s3-integrator" }
```

### COS

The module doesn't deploy COS. To enable monitoring, deploy a collector, such as `opentelemetry-collector`, in the same model, relate it to COS, and pass its `cos-agent` endpoint. OpenSearch and Dashboards then send metrics, logs and dashboards through it.

```hcl
cos_agent_integration = { name = "opentelemetry-collector", endpoint = "cos-agent" }
```

### OpenSearch Dashboards

```hcl
opensearch_dashboards = {}
```

Set `opensearch_dashboards.tls = true` to give Dashboards its own certificate from the TLS provider. Dashboards then serves `https`.

### TLS

The module requires a TLS provider. By default, it deploys `self-signed-certificates`. To use your own provider, set `certificates_integration`:

```hcl
certificates_integration = { kind = "offer", url = "admin/pki.vault" }
```
