# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

locals {

  backups_enabled         = var.backups-integrator != null
  dashboards_enabled      = var.opensearch-dashboards != null
  data_integrator_enabled = var.data-integrator != null

  data_integrator_model_uuid     = local.data_integrator_enabled ? coalesce(var.data-integrator.model_uuid, var.opensearch.model_uuid) : null
  data_integrator_is_cross_model = local.data_integrator_enabled && local.data_integrator_model_uuid != var.opensearch.model_uuid

  backups_model_uuid     = local.backups_enabled ? coalesce(var.backups-integrator.model_uuid, var.opensearch.model_uuid) : null
  backups_is_cross_model = local.backups_enabled && local.backups_model_uuid != var.opensearch.model_uuid

  backups_settings = {
    s3            = { base = "ubuntu@22.04", channel = "1/stable", endpoint = "s3-credentials" }
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
    local.data_integrator_enabled ? { "data-integrator" = juju_application.data-integrator[0] } : {},
    local.dashboards_enabled ? { "opensearch-dashboards" = module.opensearch-dashboards[0].application } : {},
    var.certificates_integration == null ? { "self-signed-certificates" = juju_application.self-signed-certificates[0] } : {},
    local.backups_enabled ? { "backups-integrator" = juju_application.backups-integrator[0] } : {},
  )
}
