# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

#--------------------------------------------------------
# 1. DEPLOYMENTS
#--------------------------------------------------------

# OpenSearch apps: main, failover and `apps`
module "opensearch" {
  for_each = local.opensearch_apps
  source   = "../../charm/opensearch"

  app_name           = each.key
  base               = each.value.base
  channel            = each.value.channel
  config             = each.value.config
  constraints        = each.value.constraints
  endpoint_bindings  = each.value.endpoint_bindings
  expose             = each.value.expose
  machines           = each.value.machines
  model_uuid         = each.value.model_uuid
  offered_endpoints  = each.value.offered_endpoints
  revision           = each.value.revision
  storage_directives = each.value.storage_directives
  units              = each.value.units
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
  model_uuid = var.main.model_uuid
  config     = var.self_signed_certificates.config

  constraints = var.self_signed_certificates.constraints
  machines    = length(var.self_signed_certificates.machines) > 0 ? var.self_signed_certificates.machines : null
  units       = length(var.self_signed_certificates.machines) > 0 ? null : var.self_signed_certificates.units
}

resource "juju_offer" "certificates" {
  count = var.certificates_integration == null ? 1 : 0

  name             = "${juju_application.self_signed_certificates[0].name}-certificates"
  application_name = juju_application.self_signed_certificates[0].name
  endpoints        = ["certificates"]
  model_uuid       = var.main.model_uuid
}

# OpenSearch dashboards
module "opensearch_dashboards" {
  count  = local.dashboards_enabled ? 1 : 0
  source = "git::https://github.com/canonical/opensearch-dashboards-operator.git//terraform/machine/charm/opensearch_dashboards?ref=74bd9b434a906dfb57e9baf371df71a5a3695645"

  app_name          = var.opensearch_dashboards.app_name
  base              = var.opensearch_dashboards.base
  channel           = var.opensearch_dashboards.channel
  config            = var.opensearch_dashboards.config
  constraints       = var.opensearch_dashboards.constraints
  endpoint_bindings = var.opensearch_dashboards.endpoint_bindings
  expose            = var.opensearch_dashboards.expose
  machines          = var.opensearch_dashboards.machines
  model_uuid        = var.main.model_uuid
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
  model_uuid  = var.main.model_uuid
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
  model_uuid = var.main.model_uuid
  config = merge(
    var.backups.config,
    local.backups_secret_uri != null ? { credentials = local.backups_secret_uri } : {},
    local.backups_secret_create ? { credentials = juju_secret.backups_credentials[0].secret_uri } : {},
  )

  constraints = var.backups.constraints
  machines    = length(var.backups.machines) > 0 ? var.backups.machines : null
  units       = length(var.backups.machines) > 0 ? null : 1
}

resource "juju_secret" "backups_credentials" {
  count      = local.backups_secret_create ? 1 : 0
  model_uuid = var.main.model_uuid
  name       = "${var.backups.storage_type}-integrator-credentials"
  info       = "Credentials for ${var.backups.storage_type}-integrator"

  value_wo         = local.backups_secret_value
  value_wo_version = local.backups_secret_version
}

resource "juju_access_secret" "backups_credentials" {
  count        = local.backups_secret_create ? 1 : 0
  model_uuid   = var.main.model_uuid
  applications = [juju_application.backups[0].name]
  secret_id    = juju_secret.backups_credentials[0].secret_id
}

check "backups_credentials_source" {
  assert {
    condition     = !(local.backups_secret_uri != null && local.backups_secret_version > 0)
    error_message = "`${local.backups_secret_version_name}` will be ignored because `backups.credentials_secret_uri` is set. Set `${local.backups_secret_version_name}` to `0`."
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
    var.apps,
    var.azure_storage_secret_version,
    var.backups,
    var.backups_integration,
    var.certificates_integration,
    var.cluster_name,
    var.cos_agent_integration,
    var.data_integrator,
    var.failover,
    var.gcs_secret_version,
    var.main,
    var.offered_endpoints,
    var.opensearch_dashboards,
    var.s3_secret_version,
    var.self_signed_certificates,
  ]))

  lifecycle {
    ignore_changes = [input]
  }
}
