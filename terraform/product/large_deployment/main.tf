# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

locals {
  all_models = distinct(concat(
    [var.main.model_uuid],
    var.failover != null ? [var.failover.model_uuid] : [],
    var.apps != null ? [for app in var.apps : app.model_uuid] : [],
  ))

  # Map each model to its OpenSearch apps
  opensearch_apps_per_model = {
    for model in local.all_models : model => flatten(concat(
      model == var.main.model_uuid ? [var.main.app_name] : [],
      var.failover != null && model == var.failover.model_uuid ? [var.failover.app_name] : [],
      var.apps != null ? [for app in var.apps : app.app_name if app.model_uuid == model] : [],
    ))
  }
}

#--------------------------------------------------------
# 1. DEPLOYMENTS
#--------------------------------------------------------

# deploy all opensearch apps as per the large deployment charm module
module "opensearch" {
  source                   = "../../charm/large_deployment"
  cluster_name             = var.cluster_name
  main                     = var.main
  failover                 = var.failover
  apps                     = var.apps
  self-signed-certificates = var.self-signed-certificates
}

# opensearch-dashboards in the main model
module "opensearch-dashboards" {
  source     = "git::https://github.com/canonical/opensearch-dashboards-operator//terraform?ref=DPE-8947-upgrade-terraform-modules-1.0.0"
  model_uuid = var.main.model_uuid

  channel  = var.opensearch-dashboards.channel
  revision = var.opensearch-dashboards.revision
  base     = var.opensearch-dashboards.base

  app_name          = var.opensearch-dashboards.app_name
  units             = var.opensearch-dashboards.units
  config            = var.opensearch-dashboards.config
  constraints       = var.opensearch-dashboards.constraints
  endpoint_bindings = var.opensearch-dashboards.endpoint_bindings
  machines          = var.opensearch-dashboards.machines
}

# data-integrator in the main model
resource "juju_application" "data-integrator" {
  charm {
    name     = "data-integrator"
    channel  = var.data-integrator.channel
    revision = var.data-integrator.revision
    base     = var.data-integrator.base
  }
  model_uuid = var.main.model_uuid
  config     = var.data-integrator.config

  constraints = var.data-integrator.constraints
  machines    = (var.data-integrator.machines == null || length(var.data-integrator.machines) == 0) ? null : var.data-integrator.machines
}

# s3 or azure integrator in the main model
resource "juju_application" "backups-integrator" {
  charm {
    name     = "${var.backups-integrator.storage_type}-integrator"
    channel  = var.backups-integrator.channel
    revision = var.backups-integrator.revision
    base     = var.backups-integrator.base
  }
  model_uuid = var.main.model_uuid
  config     = var.backups-integrator.config

  constraints = var.backups-integrator.constraints
  machines    = (var.backups-integrator.machines == null || length(var.backups-integrator.machines) == 0) ? null : var.backups-integrator.machines
}

# grafana agent in all models
resource "juju_application" "grafana_agents" {
  for_each = toset(local.all_models)

  charm {
    name     = "grafana-agent"
    channel  = var.grafana-agent.channel
    revision = var.grafana-agent.revision
  }
  model_uuid = each.value
  config     = var.grafana-agent.config
}

#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

# Integrate the dashboards with the self-signed-certificates operator if needed
resource "juju_integration" "opensearch_dashboards-tls-integration" {
  for_each = var.opensearch-dashboards.tls ? { "integrate" = true } : {}

  model_uuid = var.main.model_uuid

  application {
    name = var.opensearch-dashboards.app_name
  }

  application {
    name = module.opensearch.app_names["self-signed-certificates"]
  }

  depends_on = [
    module.opensearch,
    module.opensearch-dashboards,
  ]
}

# integrate the dashboards with the opensearch main
resource "juju_integration" "opensearch_dashboards-opensearch_main-integration" {
  model_uuid = var.main.model_uuid

  application {
    name = var.opensearch-dashboards.app_name
  }
  application {
    name = var.main.app_name
  }

  depends_on = [
    module.opensearch,
    module.opensearch-dashboards,
  ]
}

# integrate the s3/azure integrator with the opensearch main
resource "juju_integration" "backups_integrator-opensearch_main-integration" {
  model_uuid = var.main.model_uuid

  application {
    name = juju_application.backups-integrator.name
  }
  application {
    name = var.main.app_name
  }

  depends_on = [
    module.opensearch,
    juju_application.backups-integrator,
  ]
}

# integrate the data integrator with the opensearch main
resource "juju_integration" "data_integrator-opensearch_main-integration" {
  model_uuid = var.main.model_uuid

  application {
    name = juju_application.data-integrator.name
  }
  application {
    name = var.main.app_name
  }

  depends_on = [
    module.opensearch,
    juju_application.data-integrator,
  ]
}

# Integrate the grafana-agent in each model with all the opensearch apps
resource "juju_integration" "grafana_agent_opensearch_integrations" {
  for_each = merge([
    for model, apps in local.opensearch_apps_per_model : {
      for app in apps : "${model}-${app}" => {
        model = model
        app   = app
      }
    }
  ]...)
  model_uuid = each.value.model

  application {
    name = each.value.app
  }

  application {
    name = juju_application.grafana_agents[each.value.model_uuid].name
  }

  depends_on = [
    juju_application.grafana_agents,
    module.opensearch,
  ]
}

# Integrate the grafana-agent in the main model with the opensearch-dashboards apps
resource "juju_integration" "grafana_agent_opensearch-dashboards_integrations" {
  model_uuid = var.main.model_uuid

  application {
    name = juju_application.grafana_agents[var.main.model_uuid].name
  }
  application {
    name = var.opensearch-dashboards.app_name
  }

  depends_on = [
    juju_application.grafana_agents,
    module.opensearch-dashboards,
  ]
}
