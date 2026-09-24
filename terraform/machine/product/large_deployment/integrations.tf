# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

resource "juju_integration" "opensearch-tls-integration" {
  for_each   = local.opensearch_apps
  model_uuid = each.value.model_uuid

  application {
    name     = each.value.requires.certificates.name
    endpoint = each.value.requires.certificates.endpoint
  }

  application {
    name      = local.certificates_targets[each.key].kind == "endpoint" ? local.certificates_targets[each.key].name : null
    endpoint  = local.certificates_targets[each.key].kind == "endpoint" ? local.certificates_targets[each.key].endpoint : null
    offer_url = local.certificates_targets[each.key].kind == "offer" ? local.certificates_targets[each.key].url : null
  }

  lifecycle {
    precondition {
      condition     = local.certificates_targets[each.key].kind == "offer" || each.value.model_uuid == local.main_model_uuid
      error_message = "A certificates_integration with kind = \"endpoint\" only works for apps in the main model. Use kind = \"offer\"."
    }
  }
}

resource "juju_integration" "opensearch_dashboards-tls-integration" {
  count      = try(var.opensearch-dashboards.tls, false) ? 1 : 0
  model_uuid = local.main_model_uuid

  application {
    name     = module.opensearch-dashboards[0].requires.certificates.name
    endpoint = module.opensearch-dashboards[0].requires.certificates.endpoint
  }

  application {
    name      = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.name : null
    endpoint  = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.endpoint : null
    offer_url = local.certificates_provider.kind == "offer" ? local.certificates_provider.url : null
  }
}

resource "juju_integration" "main_orchestrator-peer_cluster-integration" {
  for_each   = { for key, app in local.opensearch_apps : key => app if key != var.main.app_name }
  model_uuid = each.value.model_uuid

  application {
    name     = each.value.requires.peer_cluster.name
    endpoint = each.value.requires.peer_cluster.endpoint
  }

  application {
    name      = each.value.model_uuid == local.main_model_uuid ? module.opensearch_main.provides.peer_cluster_orchestrator.name : null
    endpoint  = each.value.model_uuid == local.main_model_uuid ? module.opensearch_main.provides.peer_cluster_orchestrator.endpoint : null
    offer_url = each.value.model_uuid == local.main_model_uuid ? null : juju_offer.main_orchestrator.url
  }
}

resource "juju_integration" "failover_orchestrator-peer_cluster-integration" {
  for_each   = local.failover_enabled ? { for key, app in local.opensearch_apps : key => app if contains(keys(local.apps), key) } : {}
  model_uuid = each.value.model_uuid

  application {
    name     = each.value.requires.peer_cluster.name
    endpoint = each.value.requires.peer_cluster.endpoint
  }

  application {
    name      = each.value.model_uuid == local.failover_model_uuid ? module.opensearch_failover[0].provides.peer_cluster_orchestrator.name : null
    endpoint  = each.value.model_uuid == local.failover_model_uuid ? module.opensearch_failover[0].provides.peer_cluster_orchestrator.endpoint : null
    offer_url = each.value.model_uuid == local.failover_model_uuid ? null : juju_offer.failover_orchestrator[0].url
  }
}

resource "juju_integration" "opensearch_dashboards-opensearch-integration" {
  count      = local.dashboards_enabled ? 1 : 0
  model_uuid = local.main_model_uuid

  application {
    name     = module.opensearch-dashboards[0].requires.opensearch_client.name
    endpoint = module.opensearch-dashboards[0].requires.opensearch_client.endpoint
  }

  application {
    name     = module.opensearch_main.provides.opensearch_client.name
    endpoint = module.opensearch_main.provides.opensearch_client.endpoint
  }
}

resource "juju_integration" "backups_integrator-opensearch-integration" {
  count      = local.backups_enabled ? 1 : 0
  model_uuid = local.main_model_uuid

  application {
    name      = local.backups_is_cross_model ? null : juju_application.backups-integrator[0].name
    endpoint  = local.backups_is_cross_model ? null : local.backups_settings[var.backups-integrator.storage_type].endpoint
    offer_url = local.backups_is_cross_model ? juju_offer.backups_credentials[0].url : null
  }

  application {
    name     = module.opensearch_main.application.name
    endpoint = local.backups_settings[var.backups-integrator.storage_type].endpoint
  }
}

resource "juju_integration" "data_integrator-opensearch-integration" {
  count      = local.data_integrator_enabled ? 1 : 0
  model_uuid = local.data_integrator_model_uuid

  application {
    name     = module.data-integrator[0].requires.opensearch.name
    endpoint = module.data-integrator[0].requires.opensearch.endpoint
  }

  application {
    name      = local.data_integrator_is_cross_model ? null : module.opensearch_main.provides.opensearch_client.name
    endpoint  = local.data_integrator_is_cross_model ? null : module.opensearch_main.provides.opensearch_client.endpoint
    offer_url = local.data_integrator_is_cross_model ? juju_offer.opensearch_client[0].url : null
  }
}

resource "juju_integration" "cos_agent-opensearch-integration" {
  for_each   = { for key, agent in var.cos_agent_integrations : key => agent if contains(keys(local.cos_agent_targets), key) }
  model_uuid = local.cos_agent_targets[each.key].model_uuid

  application {
    name     = each.value.name
    endpoint = each.value.endpoint
  }

  application {
    name     = local.cos_agent_targets[each.key].provides.cos_agent.name
    endpoint = local.cos_agent_targets[each.key].provides.cos_agent.endpoint
  }
}
