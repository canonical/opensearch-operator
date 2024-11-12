# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "opensearch" {

  charm {
    name     = "opensearch"
    channel  = var.channel
    revision = var.revision
  }
  config      = var.config
  model       = var.model
  name        = var.app_name
  units       = var.units
  constraints = var.constraints

  placement = join(",", var.machines)

  endpoint_bindings = [
    for k, v in var.endpoint_bindings : {
      endpoint = k, space = v
    }
  ]

  storage_directives = var.storage

  lifecycle {
    precondition {
      condition     = length(var.machines) == var.units
      error_message = "Machine count does not match unit count"
    }
    precondition {
      condition     = length(var.storage["count"]) <= 1
      error_message = "Only one storage is supported"
    }
  }
}
