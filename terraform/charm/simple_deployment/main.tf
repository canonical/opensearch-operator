# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# Identify if the current model is where the main orchestrator resides to deploy the tls provider
locals {
  is_main_orchestrator = !lookup(var.config, "init_hold", false)
}

# Resolve model UUID (provider requires model_uuid, not model)
data "juju_model" "this" {
  name = var.model
}

#--------------------------------------------------------
# 1. DEPLOYMENTS
#--------------------------------------------------------

# Deploy required applications
resource "juju_application" "opensearch" {
  model_uuid = data.juju_model.this.uuid

  charm {
    name     = "opensearch"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  name               = var.app_name
  config             = var.config
  units              = var.units
  constraints        = var.constraints
  storage_directives = var.storage

  dynamic "expose" {
    for_each = var.expose ? [1] : []
    content {}
  }

  # placement is not supported by juju_application; keep machines handling external for now
  # placement = join(",", var.machines)  # <-- removed on purpose

  # Keep as a list of objects if your provider version expects this form
  endpoint_bindings = [
    for k, v in var.endpoint_bindings : {
      endpoint = k, space = v
    }
  ]

  lifecycle {
    precondition {
      condition     = (local.is_main_orchestrator && (var.main_model == null || var.model == var.main_model)) || (!local.is_main_orchestrator && var.main_model != null)
      error_message = "The main_model should either be null or equal to the model for main orchestrators."
    }
  }
}

# Deploy the self-signed-certificates operator if main orchestrator
resource "juju_application" "self_signed_certificates" {
  for_each  = local.is_main_orchestrator ? { "deployed" = true } : {}
  model_uuid = data.juju_model.this.uuid

  charm {
    name     = "self-signed-certificates"
    channel  = var.self_signed_certificates.channel
    revision = var.self_signed_certificates.revision
    base     = var.self_signed_certificates.base
  }

  name         = "self-signed-certificates"
  config       = var.self_signed_certificates.config
  units       = 1
  constraints = var.self_signed_certificates.constraints

}

#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

# Integrations (same-model TLS)
resource "juju_integration" "tls-opensearch-same-model_integration" {
  for_each  = (local.is_main_orchestrator || var.model == var.main_model) ? { "local" = true } : {}
  model_uuid = data.juju_model.this.uuid

  application {
    name = "self-signed-certificates" # fixed name so subsequent same-model apps can reuse
  }

  application {
    name = juju_application.opensearch.name
  }

  depends_on = [
    juju_application.self_signed_certificates,
    juju_application.opensearch,
  ]
}
