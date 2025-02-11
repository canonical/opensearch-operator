# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

locals {
  all_models = distinct(concat(
    [var.main.model],
    var.failover != null ? [var.failover.model] : [],
    var.apps != null ? [for app in var.apps : app.model] : [],
  ))

  # Map each model to its OpenSearch apps
  opensearch_apps_per_model = { for model in local.all_models : model => flatten(concat(
    model == var.main.model ? [var.main.app_name] : [],
    var.failover != null && model == var.failover.model ? [var.failover.app_name] : [],
    var.apps != null ? [for app in var.apps : app.app_name if app.model == model] : [],
  )) }
}

#--------------------------------------------------------
# 1. DEPLOYMENTS
#--------------------------------------------------------

# deploy all opensearch apps as per the large deployment charm module
module "opensearch" {
  source       = "../../charm/large_deployment"
  cluster_name = var.cluster_name
  main         = var.main
  failover     = var.failover
  apps         = var.apps
}

# opensearch-dashboards in the main model
module "opensearch-dashboards" {
  source = "git::https://github.com/canonical/opensearch-dashboards-operator//terraform?ref=2/edge"
  model  = var.main.model
}

# data-integrator in the main model
resource "juju_application" "data-integrator" {
  charm {
    name    = "data-integrator"
    channel = "latest/stable"
  }
  model  = var.main.model
  config = var.data-integrator
}

# s3 or azure integrator in the main model
resource "juju_application" "backups-integrator" {
  charm {
    name    = "${var.backups-integrator.storage_type}-integrator"
    channel = "latest/stable"
  }
  model  = var.main.model
  config = var.backups-integrator.config
}

# grafana agent in all models
resource "juju_application" "grafana_agents" {
  for_each = toset(local.all_models)

  charm {
    name    = "grafana-agent"
    channel = "latest/stable"
  }
  model = each.value
}

#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

# integrate the dashboards with the opensearch main
resource "juju_integration" "opensearch_dashboards-opensearch_main-integration" {
  model = var.main.model

  application {
    name = module.opensearch-dashboards.app_name
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
  model = var.main.model

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
  model = var.main.model

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

  model = each.value.model

  application {
    name = each.value.app
  }

  application {
    name = juju_application.grafana_agents[each.value.model].name
  }

  depends_on = [
    juju_application.grafana_agents,
    module.opensearch,
  ]
}

# Integrate the grafana-agent in the main model with the opensearch-dashboards apps
resource "juju_integration" "grafana_agent_opensearch-dashboards_integrations" {
  model = var.main.model

  application {
    name = juju_application.grafana_agents[var.main.model].name
  }
  application {
    name = module.opensearch-dashboards.app_name
  }

  depends_on = [
    juju_application.grafana_agents,
    module.opensearch-dashboards,
  ]
}
