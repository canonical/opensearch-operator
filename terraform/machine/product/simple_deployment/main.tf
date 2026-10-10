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
resource "juju_application" "self-signed-certificates" {
  count = var.certificates_integration == null ? 1 : 0

  charm {
    name     = "self-signed-certificates"
    channel  = var.self-signed-certificates.channel
    revision = var.self-signed-certificates.revision
    base     = var.self-signed-certificates.base
  }
  name       = "self-signed-certificates"
  model_uuid = var.opensearch.model_uuid
  config     = var.self-signed-certificates.config

  constraints = var.self-signed-certificates.constraints
  machines    = length(var.self-signed-certificates.machines) > 0 ? var.self-signed-certificates.machines : null
  units       = length(var.self-signed-certificates.machines) > 0 ? null : var.self-signed-certificates.units
}

# OpenSearch dashboards
module "opensearch-dashboards" {
  count  = local.dashboards_enabled ? 1 : 0
  source = "git::https://github.com/canonical/opensearch-dashboards-operator.git//terraform/machine/charm/opensearch_dashboards?ref=8b93e9fd8c686f6d4cf8617380d5d8c07c2d8786"

  app_name          = var.opensearch-dashboards.app_name
  base              = var.opensearch-dashboards.base
  channel           = var.opensearch-dashboards.channel
  config            = var.opensearch-dashboards.config
  constraints       = var.opensearch-dashboards.constraints
  endpoint_bindings = var.opensearch-dashboards.endpoint_bindings
  expose            = var.opensearch-dashboards.expose
  machines          = var.opensearch-dashboards.machines
  model_uuid        = var.opensearch.model_uuid
  revision          = var.opensearch-dashboards.revision
  units             = var.opensearch-dashboards.units
}

# Integrator apps
module "data-integrator" {
  count  = local.data_integrator_enabled ? 1 : 0
  source = "git::https://github.com/canonical/data-integrator.git//terraform/charm/data_integrator?ref=rev519"

  base        = var.data-integrator.base
  channel     = var.data-integrator.channel
  config      = var.data-integrator.config
  constraints = var.data-integrator.constraints
  machines    = var.data-integrator.machines
  model_uuid  = var.opensearch.model_uuid
  revision    = var.data-integrator.revision
}

resource "juju_application" "backups-integrator" {
  count = local.backups_enabled ? 1 : 0

  charm {
    name     = "${var.backups-integrator.storage_type}-integrator"
    channel  = coalesce(var.backups-integrator.channel, local.backups_settings[var.backups-integrator.storage_type].channel)
    revision = var.backups-integrator.revision
    base     = coalesce(var.backups-integrator.base, local.backups_settings[var.backups-integrator.storage_type].base)
  }
  model_uuid = var.opensearch.model_uuid
  config = merge(
    var.backups-integrator.config,
    local.backups_secret_uri != null ? { credentials = local.backups_secret_uri } : {},
    local.backups_secret_create ? { credentials = juju_secret.backups_credentials[0].secret_uri } : {},
  )

  constraints = var.backups-integrator.constraints
  machines    = length(var.backups-integrator.machines) > 0 ? var.backups-integrator.machines : null
  units       = length(var.backups-integrator.machines) > 0 ? null : 1
}

resource "juju_secret" "backups_credentials" {
  count      = local.backups_secret_create ? 1 : 0
  model_uuid = var.opensearch.model_uuid
  name       = "${var.backups-integrator.storage_type}-integrator-credentials"
  info       = "Credentials for ${var.backups-integrator.storage_type}-integrator"

  value_wo         = local.backups_secret_value
  value_wo_version = local.backups_secret_version
}

resource "juju_access_secret" "backups_credentials" {
  count        = local.backups_secret_create ? 1 : 0
  model_uuid   = var.opensearch.model_uuid
  applications = [juju_application.backups-integrator[0].name]
  secret_id    = juju_secret.backups_credentials[0].secret_id
}

check "backups_credentials_source" {
  assert {
    condition     = !(local.backups_secret_uri != null && local.backups_secret_version > 0)
    error_message = "`${local.backups_secret_version_name}` will be ignored because `backups-integrator.credentials_secret_uri` is set. Set `${local.backups_secret_version_name}` to `0`."
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
    var.azure_storage_secret_version,
    var.backups-integrator,
    var.backups_integration,
    var.certificates_integration,
    var.cos_agent_integration,
    var.data-integrator,
    var.gcs_secret_version,
    var.offered_endpoints,
    var.opensearch,
    var.opensearch-dashboards,
    var.s3_secret_version,
    var.self-signed-certificates,
  ]))

  lifecycle {
    ignore_changes = [input]
  }
}
