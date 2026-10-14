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

  certificates_offer = var.certificates_integration != null ? var.certificates_integration : {
    kind     = "offer"
    name     = null
    endpoint = null
    url      = juju_offer.certificates[0].url
  }

  components = merge(
    { for name, app in module.opensearch : name => app.application },
    local.data_integrator_enabled ? { "data_integrator" = module.data_integrator[0].application } : {},
    local.dashboards_enabled ? { "opensearch_dashboards" = module.opensearch_dashboards[0].application } : {},
    var.certificates_integration == null ? { "self_signed_certificates" = juju_application.self_signed_certificates[0] } : {},
    local.backups_enabled ? { "backups" = juju_application.backups[0] } : {},
  )

  cos_collectors = merge(
    { for app in var.apps : app.app_name => app.cos_collector },
    local.failover_enabled ? { (var.failover.app_name) = var.failover.cos_collector } : {},
    { (var.main.app_name) = null },
  )

  dashboards_enabled        = var.opensearch_dashboards != null
  data_integrator_enabled   = var.data_integrator != null
  failover_app              = local.failover_enabled ? module.opensearch[var.failover.app_name] : null
  failover_election_timeout = 1800
  failover_enabled          = var.failover != null

  failover_orchestrator = local.failover_enabled ? {
    endpoint = merge(local.failover_app.provides.peer_cluster_orchestrator, { url = null })
    offer    = merge(local.failover_app.offers.peer_cluster_orchestrator, { name = null, endpoint = null })
  } : null

  grafana_dashboard_targets = { for name, collector in local.cos_collectors : name => collector == null ? var.grafana_dashboard_integration : { kind = "endpoint", name = collector, endpoint = "grafana-dashboards-consumer", url = null } }

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
      grafana_opensearch_dashboards = local.dashboards_enabled && var.grafana_dashboard_integration != null ? {
        app    = module.opensearch_dashboards[0].provides.grafana_dashboard
        target = var.grafana_dashboard_integration
      } : null
      ingress_opensearch_dashboards = local.dashboards_enabled && var.ingress_integration != null ? {
        app    = module.opensearch_dashboards[0].requires.ingress
        target = var.ingress_integration
      } : null
      logging_opensearch_dashboards = local.dashboards_enabled && var.logging_integration != null ? {
        app    = module.opensearch_dashboards[0].requires.logging
        target = var.logging_integration
      } : null
      metrics_opensearch_dashboards = local.dashboards_enabled && var.metrics_endpoint_integration != null ? {
        app    = module.opensearch_dashboards[0].provides.metrics_endpoint
        target = var.metrics_endpoint_integration
      } : null
      peer_cluster_orchestrators = local.failover_enabled ? {
        model_uuid = local.opensearch_apps[var.failover.app_name].model_uuid
        app        = local.failover_app.requires.peer_cluster
        target     = local.opensearch_apps[var.failover.app_name].in_main_model ? local.main_orchestrator.endpoint : local.main_orchestrator.offer
      } : null
      tls_opensearch_dashboards = try(var.opensearch_dashboards.tls, false) ? {
        app    = module.opensearch_dashboards[0].requires.certificates
        target = local.certificates_provider
      } : null
    },
    { for name, app in local.opensearch_apps : "grafana_${name}" => {
      model_uuid = app.model_uuid
      app        = module.opensearch[name].provides.grafana_dashboard
      target     = local.grafana_dashboard_targets[name]
    } if local.grafana_dashboard_targets[name] != null },
    { for name, app in local.opensearch_apps : "logging_${name}" => {
      model_uuid = app.model_uuid
      app        = module.opensearch[name].requires.logging
      target     = local.logging_targets[name]
    } if local.logging_targets[name] != null },
    { for name, app in local.opensearch_apps : "metrics_${name}" => {
      model_uuid = app.model_uuid
      app        = module.opensearch[name].provides.metrics_endpoint
      target     = local.metrics_endpoint_targets[name]
    } if local.metrics_endpoint_targets[name] != null },
    { for name in local.non_manager_apps : "peer_cluster_failover_${name}" => {
      model_uuid = local.opensearch_apps[name].model_uuid
      app        = module.opensearch[name].requires.peer_cluster
      target     = local.opensearch_apps[name].in_failover_model ? local.failover_orchestrator.endpoint : local.failover_orchestrator.offer
    } if local.failover_enabled },
    { for name in local.non_manager_apps : "peer_cluster_main_${name}" => {
      model_uuid = local.opensearch_apps[name].model_uuid
      app        = module.opensearch[name].requires.peer_cluster
      target     = local.opensearch_apps[name].in_main_model ? local.main_orchestrator.endpoint : local.main_orchestrator.offer
    } },
    { for name, app in local.opensearch_apps : "tls_${name}" => {
      model_uuid = app.model_uuid
      app        = module.opensearch[name].requires.certificates
      target     = app.in_main_model ? local.certificates_provider : local.certificates_offer
    } },
    ) : key => {
    model_uuid = try(value.model_uuid, var.main.model_uuid)
    app        = { name = value.app.name, endpoint = value.app.endpoint }
    target     = { kind = value.target.kind, name = value.target.name, endpoint = value.target.endpoint, url = try(value.target.url, null) }
  } if value != null }

  logging_targets = { for name, collector in local.cos_collectors : name => collector == null ? var.logging_integration : { kind = "endpoint", name = collector, endpoint = "receive-loki-logs", url = null } }

  main_app = module.opensearch[var.main.app_name]

  main_orchestrator = {
    endpoint = merge(local.main_app.provides.peer_cluster_orchestrator, { url = null })
    offer    = merge(local.main_app.offers.peer_cluster_orchestrator, { name = null, endpoint = null })
  }

  manager_apps = [
    for app in var.apps : app.app_name if lookup(app.config, "roles", "") == "" || contains([for role in split(",", lookup(app.config, "roles", "")) : trimspace(role)], "cluster_manager")
  ]

  manager_integrations = merge(
    { for name in local.manager_apps : "peer_cluster_failover_${name}" => {
      model_uuid = local.opensearch_apps[name].model_uuid
      app        = module.opensearch[name].requires.peer_cluster
      target     = local.opensearch_apps[name].in_failover_model ? local.failover_orchestrator.endpoint : local.failover_orchestrator.offer
    } },
    { for name in local.manager_apps : "peer_cluster_main_${name}" => {
      model_uuid = local.opensearch_apps[name].model_uuid
      app        = module.opensearch[name].requires.peer_cluster
      target     = local.opensearch_apps[name].in_main_model ? local.main_orchestrator.endpoint : local.main_orchestrator.offer
    } },
  )

  metrics_endpoint_targets = { for name, collector in local.cos_collectors : name => collector == null ? var.metrics_endpoint_integration : { kind = "endpoint", name = collector, endpoint = "metrics-endpoint", url = null } }

  non_manager_apps = [for app in var.apps : app.app_name if !contains(local.manager_apps, app.app_name)]

  opensearch_apps = merge(
    { for app in var.apps : app.app_name => merge(app, {
      config        = merge(app.config, { "cluster_name" : var.cluster_name, "init_hold" : "true" })
      model_uuid    = coalesce(app.model_uuid, var.main.model_uuid)
      in_main_model = app.model_uuid == null ? true : app.model_uuid == var.main.model_uuid
      in_failover_model = local.failover_enabled ? (
        app.model_uuid == var.failover.model_uuid ? true :
        coalesce(app.model_uuid, var.main.model_uuid) == coalesce(var.failover.model_uuid, var.main.model_uuid)
      ) : false
      offered_endpoints = []
    }) },
    local.failover_enabled ? { (var.failover.app_name) = merge(var.failover, {
      config            = merge({ "roles" : "cluster_manager" }, var.failover.config, { "cluster_name" : var.cluster_name, "init_hold" : "true" })
      model_uuid        = coalesce(var.failover.model_uuid, var.main.model_uuid)
      in_main_model     = var.failover.model_uuid == null ? true : var.failover.model_uuid == var.main.model_uuid
      offered_endpoints = ["peer-cluster-orchestrator"]
    }) } : {},
    { (var.main.app_name) = merge(var.main, {
      config            = merge({ "roles" : "cluster_manager" }, var.main.config, { "cluster_name" : var.cluster_name, "init_hold" : "false" })
      in_main_model     = true
      offered_endpoints = concat(["peer-cluster-orchestrator"], var.offered_endpoints)
    }) },
  )

  single_model = alltrue([for app in local.opensearch_apps : app.in_main_model])
}
