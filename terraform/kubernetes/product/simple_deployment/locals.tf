# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

locals {
  backups_enabled        = var.backups-integrator != null
  backups_is_cross_model = local.backups_enabled && local.backups_model_uuid != var.opensearch.model_uuid
  backups_model_uuid     = local.backups_enabled ? coalesce(var.backups-integrator.model_uuid, var.opensearch.model_uuid) : null

  # user-provided secret takes priority
  backups_secret_uri = local.backups_enabled ? var.backups-integrator.credentials_secret_uri : null
  backups_keys_set = local.backups_enabled ? (
    var.backups-integrator.storage_type == "s3" ? nonsensitive(var.s3_access_key != null && var.s3_secret_key != null) :
    var.backups-integrator.storage_type == "gcs" ? nonsensitive(var.gcs_secret_key != null) :
    nonsensitive(var.azure_storage_secret_key != null)
  ) : false
  backups_secret_create = local.backups_secret_uri == null && local.backups_keys_set

  backups_secret_value = local.backups_secret_create ? (
    var.backups-integrator.storage_type == "s3" ? tomap({ access-key = var.s3_access_key, secret-key = var.s3_secret_key }) :
    var.backups-integrator.storage_type == "gcs" ? tomap({ secret-key = var.gcs_secret_key }) :
    tomap({ secret-key = var.azure_storage_secret_key })
  ) : null

  backups_settings = {
    s3            = { base = "ubuntu@24.04", channel = "2/stable", endpoint = "s3-credentials" }
    azure-storage = { base = "ubuntu@22.04", channel = "latest/edge", endpoint = "azure-credentials" }
    gcs           = { base = "ubuntu@24.04", channel = "1/edge", endpoint = "gcs-credentials" }
  }

  certificates_provider = var.certificates_integration != null ? var.certificates_integration : {
    kind     = "endpoint"
    name     = juju_application.self-signed-certificates[0].name
    endpoint = "certificates"
    url      = null
  }

  components = merge(
    {
      "opensearch" = module.opensearch.application
    },
    local.data_integrator_enabled ? { "data-integrator" = module.data-integrator[0].application } : {},
    local.dashboards_enabled ? { "opensearch-dashboards" = module.opensearch-dashboards[0].application } : {},
    var.certificates_integration == null ? { "self-signed-certificates" = juju_application.self-signed-certificates[0] } : {},
    local.backups_enabled ? { "backups-integrator" = juju_application.backups-integrator[0] } : {},
  )

  dashboards_enabled             = var.opensearch-dashboards != null
  data_integrator_enabled        = var.data-integrator != null
  data_integrator_is_cross_model = local.data_integrator_enabled && local.data_integrator_model_uuid != var.opensearch.model_uuid
  data_integrator_model_uuid     = local.data_integrator_enabled ? coalesce(var.data-integrator.model_uuid, var.opensearch.model_uuid) : null
}
