# Terraform module for opensearch-operator

This is a Terraform module facilitating the deployment of the OpenSearch charm with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs).

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
| backups-integrator | Configuration for the optional backup integrator | `null` | no |
| certificates_integration | External TLS endpoint or offer. | `null` | no |
| cos_agent_integration | COS agent endpoint. | `null` | no |
| data-integrator | Configuration for the optional data-integrator | `null` | no |
| opensearch | OpenSearch app definition | n/a | yes |
| opensearch-dashboards | Optional OpenSearch Dashboards app definition | `null` | no |
| self-signed-certificates | Configuration for the self-signed-certificates app | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| app_names | Output of all deployed application names. |
| metadata | Product deployment metadata. |
| models | Deployed applications |
| offers | Map of offers URLs. |
| provides | Map of all 'provides' endpoints |
| requires | Map of all 'requires' endpoints |
<!-- END_TF_DOCS -->

## Usage

This module is intended to be a product module, deploying all components for a proper yet simple opensearch deployment.

It may be used as-is and directly as follows:
```
terraform plan \
  -var='opensearch={"model_uuid": "<model-uuid>"}' \
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
