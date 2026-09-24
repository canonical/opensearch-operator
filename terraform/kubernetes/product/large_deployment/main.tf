# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

#--------------------------------------------------------
# 1. DEPLOYMENTS
#--------------------------------------------------------

# main orchestrator
module "opensearch_main" {
  source = "../../charm/opensearch"

  app_name           = var.main.app_name
  base               = var.main.base
  channel            = var.main.channel
  config             = merge({ "roles" : "cluster_manager" }, var.main.config, { "cluster_name" : var.cluster_name, "init_hold" : "false" })
  constraints        = var.main.constraints
  expose             = var.main.expose
  model_uuid         = local.main_model_uuid
  resources          = var.main.resources
  revision           = var.main.revision
  storage_directives = var.main.storage_directives
  units              = var.main.units
}

# failover orchestrator
module "opensearch_failover" {
  count  = local.failover_enabled ? 1 : 0
  source = "../../charm/opensearch"

  app_name           = var.failover.app_name
  base               = var.failover.base
  channel            = var.failover.channel
  config             = merge({ "roles" : "cluster_manager" }, var.failover.config, { "cluster_name" : var.cluster_name, "init_hold" : "true" })
  constraints        = var.failover.constraints
  expose             = var.failover.expose
  model_uuid         = local.failover_model_uuid
  resources          = var.failover.resources
  revision           = var.failover.revision
  storage_directives = var.failover.storage_directives
  units              = var.failover.units
}

# non-orchestrator apps
module "opensearch_apps" {
  for_each = local.apps
  source   = "../../charm/opensearch"

  app_name           = each.value.app_name
  base               = each.value.base
  channel            = each.value.channel
  config             = merge(each.value.config, { "cluster_name" : var.cluster_name, "init_hold" : "true" })
  constraints        = each.value.constraints
  expose             = each.value.expose
  model_uuid         = each.value.model_uuid
  resources          = each.value.resources
  revision           = each.value.revision
  storage_directives = each.value.storage_directives
  units              = each.value.units
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
  model_uuid = local.main_model_uuid
  config     = var.self-signed-certificates.config

  constraints = var.self-signed-certificates.constraints
  units       = var.self-signed-certificates.units
}

# OpenSearch dashboards
module "opensearch-dashboards" {
  count  = local.dashboards_enabled ? 1 : 0
  source = "git::https://github.com/canonical/opensearch-dashboards-operator.git//terraform/kubernetes/charm/opensearch_dashboards?ref=8b93e9fd8c686f6d4cf8617380d5d8c07c2d8786"

  app_name    = var.opensearch-dashboards.app_name
  base        = var.opensearch-dashboards.base
  channel     = var.opensearch-dashboards.channel
  config      = var.opensearch-dashboards.config
  constraints = var.opensearch-dashboards.constraints
  expose      = var.opensearch-dashboards.expose
  model_uuid  = local.main_model_uuid
  resources   = var.opensearch-dashboards.resources
  revision    = var.opensearch-dashboards.revision
  units       = var.opensearch-dashboards.units
}

# Ingress provider for OpenSearch dashboards
resource "juju_application" "traefik-k8s" {
  count = local.dashboards_enabled && var.ingress_integration == null ? 1 : 0

  charm {
    name     = "traefik-k8s"
    channel  = var.traefik-k8s.channel
    revision = var.traefik-k8s.revision
    base     = var.traefik-k8s.base
  }
  name       = "traefik-k8s"
  model_uuid = local.main_model_uuid
  config     = var.traefik-k8s.config

  constraints = var.traefik-k8s.constraints
  trust       = true
  units       = var.traefik-k8s.units
}

# Integrator apps
module "data-integrator" {
  count  = local.data_integrator_enabled ? 1 : 0
  source = "git::https://github.com/canonical/data-integrator.git//terraform/charm/data_integrator?ref=rev519"

  base        = var.data-integrator.base
  channel     = var.data-integrator.channel
  config      = var.data-integrator.config
  constraints = var.data-integrator.constraints
  model_uuid  = local.data_integrator_model_uuid
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
  model_uuid = local.backups_model_uuid
  config     = var.backups-integrator.config

  constraints = var.backups-integrator.constraints
  units       = 1
}

resource "terraform_data" "validate_data_nodes" {
  input = local.fleet_roles

  lifecycle {
    precondition {
      condition     = anytrue([for roles in local.fleet_roles : roles == "" || anytrue([for role in split(",", roles) : startswith(trimspace(role), "data")])])
      error_message = "At least one OpenSearch app needs a data role."
    }
  }
}

resource "terraform_data" "validate_cluster_name" {
  input = var.cluster_name

  lifecycle {
    precondition {
      condition = alltrue([
        for config in concat([var.main.config], local.failover_enabled ? [var.failover.config] : [], [for app in var.apps : app.config]) :
        lookup(config, "cluster_name", var.cluster_name) == var.cluster_name
      ])
      error_message = "Set the cluster name with cluster_name. An app's config.cluster_name must be unset or equal to it."
    }
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
    var.backups-integrator,
    var.certificates_integration,
    var.cluster_name,
    var.data-integrator,
    var.failover,
    var.grafana_dashboard_integration,
    var.ingress_integration,
    var.logging_integration,
    var.main,
    var.metrics_endpoint_integration,
    var.opensearch-dashboards,
    var.self-signed-certificates,
    var.traefik-k8s,
  ]))

  lifecycle {
    ignore_changes = [input]
  }
}
