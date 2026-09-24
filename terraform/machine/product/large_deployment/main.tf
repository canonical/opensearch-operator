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
  endpoint_bindings  = var.main.endpoint_bindings
  expose             = var.main.expose
  machines           = var.main.machines
  model_uuid         = local.main_model_uuid
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
  endpoint_bindings  = var.failover.endpoint_bindings
  expose             = var.failover.expose
  machines           = var.failover.machines
  model_uuid         = local.failover_model_uuid
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
  endpoint_bindings  = each.value.endpoint_bindings
  expose             = each.value.expose
  machines           = each.value.machines
  model_uuid         = each.value.model_uuid
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
  machines    = length(var.self-signed-certificates.machines) > 0 ? var.self-signed-certificates.machines : null
  units       = length(var.self-signed-certificates.machines) > 0 ? null : var.self-signed-certificates.units
}

# OpenSearch dashboards
module "opensearch-dashboards" {
  count  = local.dashboards_enabled ? 1 : 0
  source = "git::https://github.com/canonical/opensearch-dashboards-operator.git//terraform/machine/charm/opensearch_dashboards?ref=8b93e9fd8c686f6d4cf8617380d5d8c07c2d8786"

  app_name          = var.opensearch-dashboards.app_name
  base              = var.opensearch-dashboards.base
  channel           = var.opensearch-dashboards.channel
  config            = var.opensearch-dashboards.config
  constraints       = var.opensearch-dashboards.constraints
  endpoint_bindings = var.opensearch-dashboards.endpoint_bindings
  expose            = var.opensearch-dashboards.expose
  machines          = var.opensearch-dashboards.machines
  model_uuid        = local.main_model_uuid
  revision          = var.opensearch-dashboards.revision
  units             = var.opensearch-dashboards.units
}

# Integrator apps
module "data-integrator" {
  count  = local.data_integrator_enabled ? 1 : 0
  source = "git::https://github.com/canonical/data-integrator.git//terraform/charm/data_integrator?ref=rev519"

  base        = var.data-integrator.base
  channel     = var.data-integrator.channel
  config      = var.data-integrator.config
  constraints = var.data-integrator.constraints
  machines    = var.data-integrator.machines
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
  machines    = length(var.backups-integrator.machines) > 0 ? var.backups-integrator.machines : null
  units       = length(var.backups-integrator.machines) > 0 ? null : 1
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
    var.cos_agent_integrations,
    var.data-integrator,
    var.failover,
    var.main,
    var.opensearch-dashboards,
    var.self-signed-certificates,
  ]))

  lifecycle {
    ignore_changes = [input]
  }
}

resource "terraform_data" "validate_cos_agent_integrations" {
  input = keys(var.cos_agent_integrations)

  lifecycle {
    precondition {
      condition     = alltrue([for key in keys(var.cos_agent_integrations) : contains(keys(local.cos_agent_targets), key)])
      error_message = "Each cos_agent_integrations key must be the name of a deployed OpenSearch or OpenSearch Dashboards app."
    }
  }
}
