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

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| app_name | Application name. | `string` | `"opensearch"` | no |
| base | The operating system on which to deploy. | `string` | `null` | no |
| channel | Charmhub channel. | `string` | `"2/edge"` | no |
| config | OpenSearch charm configuration. | `map(string)` | `{}` | no |
| constraints | Machine constraints. | `string` | `null` | no |
| endpoint_bindings | Set of endpoint bindings. | `set(object({ space = string, endpoint = optional(string) }))` | `[]` | no |
| expose | Expose the application for external access. | `list(object({ cidrs = optional(string), endpoints = optional(string), spaces = optional(string) }))` | `[]` | no |
| machines | List of machines for placement. When set, one unit is deployed on each listed machine. | `set(string)` | `[]` | no |
| model_uuid | Model UUID | `string` | n/a | yes |
| offered_endpoints | Endpoints to expose as Juju offers for cross-model integration. | `list(string)` | `[]` | no |
| revision | Charm revision | `number` | `null` | no |
| storage_directives | Map of storage directives for the charm. | `map(string)` | `{}` | no |
| units | Charm units. Ignored when `machines` is set. | `number` | `1` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| application | The deployed OpenSearch application object. |
| offers | Map of all offers exposed by this application. |
| provides | Map of all 'provides' endpoints. |
| requires | Map of all 'requires' endpoints. |
<!-- END_TF_DOCS -->

## Usage

This module is intended to be used as part of a higher-level module. When defining one, users should ensure that Terraform is aware of the `juju_model` dependency of the charm module. There are two options to do so when creating a high-level module:

### Define a `juju_model` resource
Define a `juju_model` resource and pass to the `model_uuid` input a reference to the `juju_model` resource's UUID. For example:

```
resource "juju_model" "opensearch" {
  name = "opensearch"
}

module "opensearch" {
  source     = "<path-to-this-directory>"
  model_uuid = juju_model.opensearch.uuid
}
```

### Define a `data` source
Define a `data` source and pass to the `model_uuid` input a reference to the `data.juju_model` resource's UUID. This will enable Terraform to look for a `juju_model` resource with a name attribute equal to the one provided, and apply only if this is present. Otherwise, it will fail before applying anything.

```
data "juju_model" "opensearch" {
  name  = var.model
  owner = "admin"
}

module "opensearch" {
  source     = "<path-to-this-directory>"
  model_uuid = data.juju_model.opensearch.uuid
}
```

### Add a TLS provider

The OpenSearch application will remain in a `blocked` state until its `certificates` endpoint is related to a TLS provider. This module does not deploy a TLS provider. Deploy one and relate it to the `certificates` endpoint. For example, with the self-signed-certificates charm:

```
resource "juju_application" "self-signed-certificates" {
  model_uuid = juju_model.opensearch.uuid

  charm {
    name    = "self-signed-certificates"
    channel = "1/stable"
  }
}

resource "juju_integration" "opensearch-tls-integration" {
  model_uuid = juju_model.opensearch.uuid

  application {
    name     = module.opensearch.requires.certificates.name
    endpoint = module.opensearch.requires.certificates.endpoint
  }

  application {
    name     = juju_application.self-signed-certificates.name
    endpoint = "certificates"
  }
}
```
