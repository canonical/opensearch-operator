# Terraform module for opensearch-operator

This is a Terraform module facilitating the deployment of the OpenSearch charm with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs). 

## Requirements
This module requires a `juju` model to be available. Refer to the [usage section](#usage) below for more details.

## API

### Inputs
The module offers the following configurable inputs:

| Name                       | Type                                                                                                                                                          | Description                                              | Required |
|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|----------|
| `cluster_name`             | string                                                                                                                                                        | OpenSearch full-cluster name                             | False    |
| `main`                     | object <br/>(structure as defined in simple deployment input variables)                                                                                       | Main OpenSearch orchestrator application description     | **True** |         
| `failover`                 | object <br/>(structure as defined in simple deployment input variables)                                                                                       | Failover OpenSearch orchestrator application description | False    |
| `apps`                     | list(object) <br/>(structure as defined in simple deployment input variables)                                                                                 | Non-orchestrator OpenSearch applications descriptions    | False    |
| `opensearch-dashboards`    | object <br/>(structure as defined in opensearch-dashboards input variables)                                                                                   | OpenSearch Dashboards application                        | False    |
| `backups-integrator`       | object <br/>(structure as defined in the azure-storage/s3-integrator charms, with the addition of an attribute: <br/>- `storage_type` = "s3" or "azure" <br/> | Backup (s3/azure) integrator application                 | False    |
| `data-integrator`          | object <br/>(structure as defined in the data-integrator charm)                                                                                               | data-integrator application                              | False    |
| `self-signed-certificates` | object <br/>(structure as defined in the self-signed-certificates charm)                                                                                      | self-signed-certificates application                     | False    |
| `grafana-agent`            | object <br/>(structure as defined in the grafana-agent charm)                                                                                                 | grafana-agent application                                | False    |


### Outputs
When applied, the module exports the following outputs:

| Name        | Description                               |
|-------------|-------------------------------------------|
| `app_names` | Map of List of deployed application names |
| `provides`  | Map of `provides` endpoints               |
| `requires`  | Map of `requires` endpoints               |
| `offers`    | Map of List of offers by the deployment   |

Example output:
```
app_names = {
  "opensearch_main" = "opensearch-main"
  "opensearch_failover" = "opensearch-failover"
  "opensearch_apps" = ["data-hot-1", "ml", "data-cold"]
  "opensearch-dashboards" = "opensearch-dashboards"
  "self-signed-certificates" = "self-signed-certificates"
  "backups-integrator" = "s3-integrator"
  "data-integrator" = "data-integrator"
  "grafana-agent" = "grafana-agent"
}
offers = {
  "opensearch_main" = "..."
  "opensearch_failover" = "..."
  "certificates" = "..."
}
provides = {
  "cos_agent" = "cos-agent"
  "opensearch_client" = "opensearch-client"
  "peer_cluster_orchestrator" = "peer-cluster-orchestrator"
}
requires = {
  "certificates" = "certificates"
  "peer_cluster" = "opensearch-client"
  "s3_credentials" = "s3-credentials"
}
```

## Usage

This module is intended to be a product module, deploying all components for a proper and large opensearch deployment.

It may be used as-is and directly as follows:
```
tf init

tf plan \

tf plan \
  -var='main={"app_name": "main", "model": "dev"}' \
  -var='failover={"app_name": "failover", "model": "dev1"}' \
  -var='apps=[{"app_name": "data1", "model": "dev2"},{"app_name": "ml", "model": "dev2"}]' \
  -var='cluster_name=test' \
  -var='backups-integrator={"config": {"bucket": "bruv"}}' \
  -out=terraform.out

tf apply terraform.out
```