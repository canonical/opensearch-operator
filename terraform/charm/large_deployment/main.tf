# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

locals {
  orchestrator_modules = merge(
    { (var.main.app_name) = module.opensearch_main },
      var.failover != null ? { (var.failover.app_name) = module.opensearch_failover } : {}
  )

  apps          = var.apps != null ? var.apps : []
  non_main_apps = concat(local.apps, var.failover != null ? [var.failover] : [])

  peer_cluster_relations = [
    for rel in flatten([
      for consumer in local.non_main_apps : [
        // Always connect to main
        {
          consumer_app       = consumer.app_name
          consumer_model     = consumer.model
          orchestrator_app   = var.main.app_name
          orchestrator_model = var.main.model
        },
        // Connect remaining apps to failover if exists
          var.failover != null && consumer.app_name != var.failover.app_name ? {
          consumer_app       = consumer.app_name
          consumer_model     = consumer.model
          orchestrator_app   = var.failover.app_name
          orchestrator_model = var.failover.model
        } : null
      ]
    ]) : rel if rel != null
  ]
}

# main orchestrator opensearch app
module "opensearch_main" {
  source                  = "../simple_deployment"

  is_orchestrator         = true
  offer_certificates      = true
  offer_opensearch        = true

  channel                 = var.main.channel
  revision                = var.main.revision
  base                    = var.main.base

  app_name                = var.main.app_name
  units                   = var.main.units
  config                  = merge(var.main.config, {"cluster_name" : var.cluster_name, "init_hold": "false"})
  model                   = var.main.model
  constraints             = var.main.constraints
  storage                 = var.main.storage
  endpoint_bindings       = var.main.endpoint_bindings
}

# failover orchestrator opensearch app
module "opensearch_failover" {
  count                   = var.failover != null ? 1 : 0
  source                  = "../simple_deployment"

  # required to flag whether this app is in the same model as the main orchestrator for TLS relation
  main_model              = var.failover.model
  is_orchestrator         = true
  offer_opensearch        = true
  certificates_offer_url  = var.failover.model != var.main.model ? module.opensearch_main.certificates_offer_url : null

  channel                 = var.failover.channel
  revision                = var.failover.revision
  base                    = var.failover.base

  app_name                = var.failover.app_name
  units                   = var.failover.units
  config                  = merge(var.failover.config, {"cluster_name" : var.cluster_name, "init_hold": "true"})
  model                   = var.failover.model
  constraints             = var.failover.constraints
  storage                 = var.failover.storage
  endpoint_bindings       = var.failover.endpoint_bindings
}

# all non orchestrator apps
module "opensearch_non_orchestrator_apps" {
  for_each                = {for idx, app in local.apps : idx => app if app != null}
  source                  = "../simple_deployment"

  # required to flag whether this app is in the same model as the main orchestrator for TLS relation
  main_model              = var.main.model

  # Cross-model offer URL (only for non-main models)
  certificates_offer_url  = each.value.model != var.main.model ? module.opensearch_main.certificates_offer_url : null
  is_orchestrator         = false
  offer_certificates      = false
  offer_opensearch        = false

  channel                 = each.value.channel
  revision                = each.value.revision
  base                    = each.value.base

  app_name                = each.value.app_name
  units                   = each.value.units
  config                  = merge(each.value.config, {"cluster_name" : var.cluster_name, "init_hold": "true"})
  model                   = each.value.model
  constraints             = each.value.constraints
  storage                 = each.value.storage
}

# large deployments peer-cluster integrations
resource "juju_integration" "peer_cluster" {
  for_each = {for idx, rel in local.peer_cluster_relations : idx => rel}
  model    = each.value.consumer_model

  # Client side (always local)
  application {
    name     = each.value.consumer_app
    endpoint = "peer-cluster"
  }

  # Consumer side: choose one of these two options depending on whether it's local or cross-model.
  dynamic "application" {
    for_each = each.value.consumer_model == each.value.orchestrator_model ? [each.value] : []
    content {
      name     = each.value.orchestrator_app
      endpoint = "peer-cluster-orchestrator"
    }
  }

  dynamic "application" {
    # Cross-model target: supply an offer_url and endpoint.
    for_each = each.value.consumer_model != each.value.orchestrator_model ? [each.value] : []
    content {
      offer_url = local.orchestrator_modules[each.value.orchestrator_app].peer_offer_url
      endpoint  = "peer-cluster-orchestrator"
    }
  }
}
