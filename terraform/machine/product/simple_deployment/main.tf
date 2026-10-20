# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

#--------------------------------------------------------
# 1. DEPLOYMENTS
#--------------------------------------------------------

# main opensearch app
module "opensearch" {
  source = "../../charm/opensearch"

  channel  = var.opensearch.channel
  revision = var.opensearch.revision
  base     = var.opensearch.base

  app_name           = var.opensearch.app_name
  units              = var.opensearch.units
  config             = merge({ "cluster_name" : "opensearch" }, var.opensearch.config)
  model_uuid         = var.opensearch.model_uuid
  constraints        = var.opensearch.constraints
  storage_directives = var.opensearch.storage_directives
  endpoint_bindings  = var.opensearch.endpoint_bindings
  machines           = var.opensearch.machines
  expose             = var.opensearch.expose
  offered_endpoints  = var.offered_endpoints
}

# TLS provider
resource "juju_application" "self_signed_certificates" {
  count = var.certificates_integration == null ? 1 : 0

  charm {
    name     = "self-signed-certificates"
    channel  = var.self_signed_certificates.channel
    revision = var.self_signed_certificates.revision
    base     = var.self_signed_certificates.base
  }
  name       = "self-signed-certificates"
  model_uuid = var.opensearch.model_uuid
  config     = var.self_signed_certificates.config

  constraints = var.self_signed_certificates.constraints
  machines    = length(var.self_signed_certificates.machines) > 0 ? var.self_signed_certificates.machines : null
  units       = length(var.self_signed_certificates.machines) > 0 ? null : var.self_signed_certificates.units
}

# OpenSearch dashboards
module "opensearch_dashboards" {
  count  = local.dashboards_enabled ? 1 : 0
  source = "git::https://github.com/canonical/opensearch-dashboards-operator.git//terraform/machine/charm/opensearch_dashboards?ref=6c84b90e07b65eeaab999d242c23143a7c298084"

  app_name          = var.opensearch_dashboards.app_name
  base              = var.opensearch_dashboards.base
  channel           = var.opensearch_dashboards.channel
  config            = var.opensearch_dashboards.config
  constraints       = var.opensearch_dashboards.constraints
  endpoint_bindings = var.opensearch_dashboards.endpoint_bindings
  expose            = var.opensearch_dashboards.expose
  machines          = var.opensearch_dashboards.machines
  model_uuid        = var.opensearch.model_uuid
  revision          = var.opensearch_dashboards.revision
  units             = var.opensearch_dashboards.units
}

# Integrator apps
module "data_integrator" {
  count  = local.data_integrator_enabled ? 1 : 0
  source = "git::https://github.com/canonical/data-integrator.git//terraform/charm/data_integrator?ref=rev519"

  base        = var.data_integrator.base
  channel     = var.data_integrator.channel
  config      = var.data_integrator.config
  constraints = var.data_integrator.constraints
  machines    = var.data_integrator.machines
  model_uuid  = var.opensearch.model_uuid
  revision    = var.data_integrator.revision
}

resource "juju_application" "backups" {
  count = local.backups_enabled ? 1 : 0

  charm {
    name     = "${var.backups.storage_type}-integrator"
    channel  = coalesce(var.backups.channel, local.backups_settings[var.backups.storage_type].channel)
    revision = var.backups.revision
    base     = coalesce(var.backups.base, local.backups_settings[var.backups.storage_type].base)
  }
  model_uuid = var.opensearch.model_uuid
  config = merge(
    var.backups.config,
    local.backups_secret_enabled ? { credentials = local.backups_secret_uri } : {},
  )

  constraints = var.backups.constraints
  machines    = length(var.backups.machines) > 0 ? var.backups.machines : null
  units       = length(var.backups.machines) > 0 ? null : 1
}

resource "juju_secret" "backups_credentials" {
  count      = local.backups_secret_create ? 1 : 0
  model_uuid = var.opensearch.model_uuid
  name       = "${var.backups.storage_type}-integrator-credentials"
  info       = "Credentials for ${var.backups.storage_type}-integrator"

  value_wo         = local.backups_secret_value
  value_wo_version = local.backups_secret_version
}

resource "juju_access_secret" "backups_credentials" {
  count        = local.backups_secret_enabled ? 1 : 0
  model_uuid   = var.opensearch.model_uuid
  applications = [juju_application.backups[0].name]
  secret_id    = regex("[^/:]+$", local.backups_secret_uri)
}

check "backups_credentials_source" {
  assert {
    condition     = !(local.backups_own_secret_uri != null && local.backups_secret_version > 0)
    error_message = "`${local.backups_secret_input}_version` is ignored because `${local.backups_secret_input}_uri` is set."
  }
}

resource "terraform_data" "deployed_at" {
  input = timestamp()

  lifecycle {
    ignore_changes = [input]
  }
}

resource "terraform_data" "updated_at" {
  input = timestamp()
  triggers_replace = sha256(jsonencode([
    var.azure_storage_secret_uri,
    var.azure_storage_secret_version,
    var.backups,
    var.backups_integration,
    var.certificates_integration,
    var.cos_agent_integration,
    var.data_integrator,
    var.gcs_secret_uri,
    var.gcs_secret_version,
    var.offered_endpoints,
    var.opensearch,
    var.opensearch_dashboards,
    var.s3_secret_uri,
    var.s3_secret_version,
    var.self_signed_certificates,
  ]))

  lifecycle {
    ignore_changes = [input]
  }
}
