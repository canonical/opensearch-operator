# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_application" "opensearch_k8s" {
  charm {
    name     = "opensearch-k8s"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }
  config             = var.config
  constraints        = var.constraints
  model_uuid         = var.model_uuid
  name               = var.app_name
  resources          = var.resources
  storage_directives = var.storage_directives
  trust              = true
  units              = var.units

  dynamic "expose" {
    for_each = var.expose

    content {
      cidrs     = expose.value.cidrs
      endpoints = expose.value.endpoints
      spaces    = expose.value.spaces
    }
  }
}
