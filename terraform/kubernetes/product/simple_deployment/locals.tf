# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

locals {
  backups_enabled = var.backups != null
  backups_provider = var.backups_integration != null ? var.backups_integration : local.backups_enabled ? {
    storage_type = var.backups.storage_type
    kind         = "endpoint"
    name         = juju_application.backups[0].name
    endpoint     = local.backups_settings[var.backups.storage_type].endpoint
    url          = null
  } : null

  # user-provided secret takes priority
  backups_secret_uri    = local.backups_enabled ? var.backups.credentials_secret_uri : null
  backups_secret_create = local.backups_secret_uri == null && local.backups_secret_version > 0
  backups_secret_version = local.backups_enabled ? (
    var.backups.storage_type == "s3" ? var.s3_secret_version :
    var.backups.storage_type == "gcs" ? var.gcs_secret_version :
    var.azure_storage_secret_version
  ) : 0
  backups_secret_version_name = local.backups_enabled ? "${replace(var.backups.storage_type, "-", "_")}_secret_version" : ""

  backups_secret_value = local.backups_secret_create ? (
    var.backups.storage_type == "s3" ? tomap({ access-key = var.s3_access_key, secret-key = var.s3_secret_key }) :
    var.backups.storage_type == "gcs" ? tomap({ secret-key = var.gcs_secret_key }) :
    tomap({ secret-key = var.azure_storage_secret_key })
  ) : null

  backups_settings = {
    s3            = { base = "ubuntu@24.04", channel = "2/stable", endpoint = "s3-credentials" }
    azure-storage = { base = "ubuntu@22.04", channel = "latest/edge", endpoint = "azure-credentials" }
    gcs           = { base = "ubuntu@24.04", channel = "1/edge", endpoint = "gcs-credentials" }
  }

  certificates_provider = var.certificates_integration != null ? var.certificates_integration : {
    kind     = "endpoint"
    name     = juju_application.self_signed_certificates[0].name
    endpoint = "certificates"
    url      = null
  }

  components = merge(
    {
      "opensearch" = module.opensearch.application
    },
    local.data_integrator_enabled ? { "data_integrator" = module.data_integrator[0].application } : {},
    local.dashboards_enabled ? { "opensearch_dashboards" = module.opensearch_dashboards[0].application } : {},
    var.certificates_integration == null ? { "self_signed_certificates" = juju_application.self_signed_certificates[0] } : {},
    local.backups_enabled ? { "backups" = juju_application.backups[0] } : {},
  )

  dashboards_enabled      = var.opensearch_dashboards != null
  data_integrator_enabled = var.data_integrator != null
}
