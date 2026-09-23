resource "juju_application" "opensearch" {
  name               = var.app_name
  model_uuid         = var.model_uuid
  config             = var.config
  constraints        = var.constraints
  endpoint_bindings  = var.endpoint_bindings
  machines           = length(var.machines) == 0 ? null : var.machines
  storage_directives = var.storage_directives
  units              = length(var.machines) == 0 ? var.units : null

  charm {
    name     = "opensearch"
    base     = var.base
    channel  = var.channel
    revision = var.revision
  }

  dynamic "expose" {
    for_each = var.expose

    content {
      cidrs     = expose.value.cidrs
      endpoints = expose.value.endpoints
      spaces    = expose.value.spaces
    }
  }
}
