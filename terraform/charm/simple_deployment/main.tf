# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Identify if the current model is where the main orchestrator resides to deploy the tls provider
locals {
  is_main_orchestrator = !lookup(var.config, "init_hold", false)
}

#--------------------------------------------------------
# 1. DEPLOYMENTS
#--------------------------------------------------------

# Deploy required applications
resource "juju_application" "opensearch" {
  charm {
    name     = "opensearch"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }
  config             = var.config
  model_uuid         = var.model_uuid
  name               = var.app_name
  units              = var.units
  constraints        = var.constraints
  storage_directives = var.storage

  dynamic "expose" {
    for_each = var.expose ? [1] : []
    content {}
  }

  # TODO: uncomment once final fixes have been added for:
  # Error: juju/terraform-provider-juju#443, juju/terraform-provider-juju#182
  # placement = join(",", var.machines)

  endpoint_bindings = [
    for k, v in var.endpoint_bindings : {
      endpoint = k, space = v
    }
  ]

  lifecycle {
    precondition {
      condition     = local.is_main_orchestrator && (var.main_model_uuid == null || var.model_uuid == var.main_model_uuid) || !local.is_main_orchestrator && var.main_model_uuid != null
      error_message = "The main_model should either be null or equal to the model for main orchestrators."
    }
  }
}

# Deploy the self-signed-certificates operator if main orchestrator
resource "juju_application" "self-signed-certificates" {
  for_each = local.is_main_orchestrator ? { "deployed" = true } : {}

  model_uuid = var.model_uuid

  charm {
    name     = "self-signed-certificates"
    channel  = var.self-signed-certificates.channel
    revision = var.self-signed-certificates.revision
    base     = var.self-signed-certificates.base
  }

  config = var.self-signed-certificates.config

  units       = 1
  constraints = var.self-signed-certificates.constraints
  machines    = (var.self-signed-certificates.machines == null || length(var.self-signed-certificates.machines) == 0) ? null : var.self-signed-certificates.machines
}


#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

# Integrations
resource "juju_integration" "tls-opensearch-same-model_integration" {
  for_each = local.is_main_orchestrator || var.model_uuid == var.main_model_uuid ? { "local" = true } : {}

  model_uuid = var.model_uuid

  application {
    name = "self-signed-certificates" # we have to fix the name for subsequent non-main same model apps
  }

  application {
    name = juju_application.opensearch.name
  }

  depends_on = [
    juju_application.self-signed-certificates,
    juju_application.opensearch,
  ]
}
