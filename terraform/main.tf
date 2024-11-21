# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "opensearch" {

  charm {
    name     = "opensearch"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }
  config      = var.config
  model       = var.model
  name        = var.app_name
  units       = var.units
  constraints = var.constraints


  # TODO: uncomment once final fixes have been added for:
  # Error: juju/terraform-provider-juju#443, juju/terraform-provider-juju#182
  # placement = join(",", var.machines)

  endpoint_bindings = [
    for k, v in var.endpoint_bindings : {
      endpoint = k, space = v
    }
  ]

  storage_directives = var.storage

  lifecycle {
    precondition {
      condition     = length(var.machines) == 0 || length(var.machines) == var.units
      error_message = "Machine count does not match unit count"
    }
    precondition {
      condition     = length(var.storage) == 0 || lookup(var.storage, "count", 0) <= 1
      error_message = "Only one storage is supported"
    }
  }
}
