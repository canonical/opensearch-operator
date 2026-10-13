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

  backups_secret_create = local.backups_secret_uri == null && local.backups_secret_version > 0
  backups_secret_uri    = local.backups_enabled ? var.backups.credentials_secret_uri : null

  backups_secret_value = local.backups_secret_create ? (
    var.backups.storage_type == "s3" ? tomap({ access-key = var.s3_access_key, secret-key = var.s3_secret_key }) :
    var.backups.storage_type == "gcs" ? tomap({ secret-key = var.gcs_secret_key }) :
    tomap({ secret-key = var.azure_storage_secret_key })
  ) : null

  backups_secret_version = local.backups_enabled ? (
    var.backups.storage_type == "s3" ? var.s3_secret_version :
    var.backups.storage_type == "gcs" ? var.gcs_secret_version :
    var.azure_storage_secret_version
  ) : 0

  backups_secret_version_name = local.backups_enabled ? "${replace(var.backups.storage_type, "-", "_")}_secret_version" : ""

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
    { for name, app in module.opensearch : name => app.application },
    local.data_integrator_enabled ? { "data_integrator" = module.data_integrator[0].application } : {},
    local.dashboards_enabled ? { "opensearch_dashboards" = module.opensearch_dashboards[0].application } : {},
    var.certificates_integration == null ? { "self_signed_certificates" = juju_application.self_signed_certificates[0] } : {},
    local.backups_enabled ? { "backups" = juju_application.backups[0] } : {},
  )

  cos_agent_provider      = var.cos_agent_integration == null ? null : merge(var.cos_agent_integration, { kind = "endpoint" })
  dashboards_enabled      = var.opensearch_dashboards != null
  data_integrator_enabled = var.data_integrator != null
  failover_app            = local.failover_enabled ? module.opensearch[var.failover.app_name] : null
  failover_enabled        = var.failover != null

  integrations = { for key, value in merge(
    {
      backups_opensearch = local.backups_provider == null ? null : {
        app    = { name = local.main_app.application.name, endpoint = local.backups_settings[local.backups_provider.storage_type].endpoint }
        target = local.backups_provider
      }
      client_data_integrator = local.data_integrator_enabled ? {
        app    = module.data_integrator[0].requires.opensearch
        target = local.main_app.provides.opensearch_client
      } : null
      client_opensearch_dashboards = local.dashboards_enabled ? {
        app    = module.opensearch_dashboards[0].requires.opensearch_client
        target = local.main_app.provides.opensearch_client
      } : null
      cos_opensearch_dashboards = local.dashboards_enabled && local.cos_agent_provider != null ? {
        app    = module.opensearch_dashboards[0].provides.cos_agent
        target = local.cos_agent_provider
      } : null
      peer_cluster_orchestrators = local.failover_enabled ? {
        app    = local.failover_app.requires.peer_cluster
        target = local.main_app.provides.peer_cluster_orchestrator
      } : null
      tls_opensearch_dashboards = try(var.opensearch_dashboards.tls, false) ? {
        app    = module.opensearch_dashboards[0].requires.certificates
        target = local.certificates_provider
      } : null
    },
    { for name, app in module.opensearch : "cos_${name}" => { app = app.provides.cos_agent, target = local.cos_agent_provider } if local.cos_agent_provider != null },
    { for name in local.non_manager_apps : "peer_cluster_failover_${name}" => { app = module.opensearch[name].requires.peer_cluster, target = local.failover_app.provides.peer_cluster_orchestrator } if local.failover_enabled },
    { for name in local.non_manager_apps : "peer_cluster_main_${name}" => { app = module.opensearch[name].requires.peer_cluster, target = local.main_app.provides.peer_cluster_orchestrator } },
    { for name, app in module.opensearch : "tls_${name}" => { app = app.requires.certificates, target = local.certificates_provider } },
    ) : key => {
    app    = { name = value.app.name, endpoint = value.app.endpoint }
    target = { kind = value.target.kind, name = value.target.name, endpoint = value.target.endpoint, url = try(value.target.url, null) }
  } if value != null }

  main_app = module.opensearch[var.main.app_name]

  manager_apps = [
    for app in var.apps : app.app_name if lookup(app.config, "roles", "") == "" || contains([for role in split(",", lookup(app.config, "roles", "")) : trimspace(role)], "cluster_manager")
  ]

  manager_integrations = merge(
    { for name in local.manager_apps : "peer_cluster_failover_${name}" => { app = module.opensearch[name].requires.peer_cluster, target = local.failover_app.provides.peer_cluster_orchestrator } },
    { for name in local.manager_apps : "peer_cluster_main_${name}" => { app = module.opensearch[name].requires.peer_cluster, target = local.main_app.provides.peer_cluster_orchestrator } },
  )

  non_manager_apps = [for app in var.apps : app.app_name if !contains(local.manager_apps, app.app_name)]

  # main, failover and `apps`, each with the config this module forces on it.
  opensearch_apps = merge(
    { for app in var.apps : app.app_name => merge(app, {
      config            = merge(app.config, { "cluster_name" : var.cluster_name, "init_hold" : "true" })
      offered_endpoints = []
    }) },
    local.failover_enabled ? { (var.failover.app_name) = merge(var.failover, {
      config            = merge({ "roles" : "cluster_manager" }, var.failover.config, { "cluster_name" : var.cluster_name, "init_hold" : "true" })
      offered_endpoints = [for endpoint in var.offered_endpoints : endpoint if endpoint == "peer-cluster-orchestrator"]
    }) } : {},
    { (var.main.app_name) = merge(var.main, {
      config            = merge({ "roles" : "cluster_manager" }, var.main.config, { "cluster_name" : var.cluster_name, "init_hold" : "false" })
      offered_endpoints = var.offered_endpoints
    }) },
  )
}
