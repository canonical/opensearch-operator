# Terraform module for opensearch-operator

This is a Terraform module facilitating the deployment of the OpenSearch charm with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs). 

## Requirements
This module requires a `juju` model to be available. Refer to the [usage section](#usage) below for more details.

## API

### Inputs
The module offers the following configurable inputs:

| Name                  | Type                                                                                                        | Description                                               | Required |
|-----------------------|-------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|----------|
| `opensearch`          | object <br/>(the object structure as defined in simple deployment input variables)                          | OpenSearch main application                               | **True** |
| `backups-integrator`  | object <br/>- `storage_type` = "s3" or "azure" <br/>- `config` as defined in the s3/azure-integrator charms | Backup config to be used in this deployment               | False    |
| `data-integrator`     | map(string, string) <br/>(map structure as defined in the data-integrator charm)                            | Config options for the data-integrator                    | False    |


### Outputs
When applied, the module exports the following outputs:

| Name       | Description                 |
|------------|-----------------------------|
| `app_name` | Application name            |
| `provides` | Map of `provides` endpoints |
| `requires` | Map of `requires` endpoints |

## Usage

This module is intended to be a product module, deploying all components for a proper yet simple opensearch deployment.

It may be used as-is and directly as follows:
```
tf plan \
  -var='opensearch={"model": "dev"}' \
  -var='backups-integrator={"config": {"bucket": "mybucket"}}' \
  -out terraform.out
  
tf apply terraform.out
```