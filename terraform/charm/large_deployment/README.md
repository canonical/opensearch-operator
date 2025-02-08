# Terraform module for opensearch-operator

This is a Terraform module facilitating the deployment of the OpenSearch charm with [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs). 

## Requirements
This module requires a `juju` model to be available. Refer to the [usage section](#usage) below for more details.

## API

### Inputs
The module offers the following configurable inputs:

| Name           | Type                                                                                      | Description                               | Required |
|----------------|-------------------------------------------------------------------------------------------|-------------------------------------------|----------|
| `cluster_name` | string                                                                                    | OpenSearch full-cluster name              | False    |
| `main`         | object <br/>(the object structure as defined in simple deployment input variables)        | Main orchestrator application description | **True**     |         
| `failover`     | object <br/>(the object structure as defined in simple deployment input variables)        | Main orchestrator application description | False    |
| `apps`         | list(object) <br/>(the object structure as defined in simple deployment input variables)  | Main orchestrator application description | False    |


### Outputs
When applied, the module exports the following outputs:

| Name                                           | Description                                                       |
|------------------------------------------------|-------------------------------------------------------------------|
| `app_name`                                     | Application name                                                  |
| `provides`                                     | Map of `provides` endpoints                                       |
| `requires`                                     | Map of `requires` endpoints                                       |
| `certificates_offer_url`                       | Offer url of the tls provider if cross-model deployments          |
| `peer_cluster_orchestrator_main_offer_url`     | Offer url of the main orchestrator if cross-model deployments     |
| `peer_cluster_orchestrator_failover_offer_url` | Offer url of the failover orchestrator if cross-model deployments |


## Usage

This module is  to be used as part of a higher-level module. When defining one, users should ensure that Terraform is aware of the `juju_model` dependency of the charm module. There are two options to do so when creating a high-level module:

### Define a `juju_model` resource
Define a `juju_model` resource and pass to the `model` input a reference to the `juju_model` resource's name. For example:

```
resource "juju_model" "opensearch-main" {
  name = "main-model"
}

...

module "opensearch" {
  source       = <path-to-this-directory>
  
  // optional
  cluster_name = "mycluster"
  
  main     = {
    app_name   = "main"
    model      = juju_model.opensearch-main.name
    ...
  }
  
  // optional
  failover = {
    app_name   = "failover"
    model      = juju_model.opensearch-failover.name
    ...
  }
  
  // optional
  apps     = [
    {
      app_name = "data1"
      model    = ..
    },
    {
      app_name = "data2"
      model    = ..
    }
  ]
}
```
Where `main, failover, apps` are defined as described in the input variables above.

### Define a `data` source
Define a `data` source and pass to the `model_name` input a reference to the `data.juju_model` resource's name. This will enable Terraform to look for a `juju_model` resource with a name attribute equal to the one provided, and apply only if this is present. Otherwise, it will fail before applying anything.

```
data "juju_model" "opensearch-main-model" {
  name = var.model
}

module "opensearch" {
  source = "<path-to-this-directory>"
  
  main   = {
    app_name   = "main"
    model      = data.juju_model.opensearch-main-model.name
    ...
  }
  ....
}
```
