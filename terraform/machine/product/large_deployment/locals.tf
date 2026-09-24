# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

locals {
  apps                   = { for app in var.apps : app.app_name => merge(app, { model_uuid = coalesce(app.model_uuid, local.main_model_uuid) }) }
  backups_enabled        = var.backups-integrator != null
  backups_is_cross_model = local.backups_enabled && local.backups_model_uuid != local.main_model_uuid
  backups_model_uuid     = local.backups_enabled ? coalesce(var.backups-integrator.model_uuid, local.main_model_uuid) : null

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

  certificates_targets = {
    for key, app in local.opensearch_apps : key => (
      local.self_signed_enabled && app.model_uuid != local.main_model_uuid ? {
        kind     = "offer"
        name     = null
        endpoint = null
        url      = juju_offer.certificates[0].url
      } : local.certificates_provider
    )
  }

  components = merge(
    {
      (var.main.app_name) = module.opensearch_main.application
    },
    local.failover_enabled ? { (var.failover.app_name) = module.opensearch_failover[0].application } : {},
    { for key, app in module.opensearch_apps : key => app.application },
    local.data_integrator_enabled ? { "data-integrator" = module.data-integrator[0].application } : {},
    local.dashboards_enabled ? { "opensearch-dashboards" = module.opensearch-dashboards[0].application } : {},
    local.self_signed_enabled ? { "self-signed-certificates" = juju_application.self-signed-certificates[0] } : {},
    local.backups_enabled ? { "backups-integrator" = juju_application.backups-integrator[0] } : {},
  )

  cos_agent_targets = merge(
    { for key, app in local.opensearch_apps : key => { model_uuid = app.model_uuid, provides = app.provides } },
    local.dashboards_enabled ? {
      (var.opensearch-dashboards.app_name) = {
        model_uuid = local.main_model_uuid
        provides   = module.opensearch-dashboards[0].provides
      }
    } : {},
  )

  dashboards_enabled             = var.opensearch-dashboards != null
  data_integrator_enabled        = var.data-integrator != null
  data_integrator_is_cross_model = local.data_integrator_enabled && local.data_integrator_model_uuid != local.main_model_uuid
  data_integrator_model_uuid     = local.data_integrator_enabled ? coalesce(var.data-integrator.model_uuid, local.main_model_uuid) : null
  failover_enabled               = var.failover != null
  failover_model_uuid            = local.failover_enabled ? coalesce(var.failover.model_uuid, local.main_model_uuid) : null

  fleet_roles = concat(
    [lookup(merge({ "roles" : "cluster_manager" }, var.main.config), "roles", "")],
    local.failover_enabled ? [lookup(merge({ "roles" : "cluster_manager" }, var.failover.config), "roles", "")] : [],
    [for app in var.apps : lookup(app.config, "roles", "")],
  )

  main_model_uuid = var.main.model_uuid

  opensearch_apps = merge(
    {
      (var.main.app_name) = {
        model_uuid = local.main_model_uuid
        provides   = module.opensearch_main.provides
        requires   = module.opensearch_main.requires
      }
    },
    local.failover_enabled ? {
      (var.failover.app_name) = {
        model_uuid = local.failover_model_uuid
        provides   = module.opensearch_failover[0].provides
        requires   = module.opensearch_failover[0].requires
      }
    } : {},
    {
      for key, app in module.opensearch_apps : key => {
        model_uuid = local.apps[key].model_uuid
        provides   = app.provides
        requires   = app.requires
      }
    },
  )

  self_signed_enabled = var.certificates_integration == null
}
