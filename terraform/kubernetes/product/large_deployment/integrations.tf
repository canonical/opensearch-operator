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

resource "juju_integration" "opensearch_dashboards-ingress-integration" {
  count      = local.dashboards_enabled ? 1 : 0
  model_uuid = local.main_model_uuid

  application {
    name     = module.opensearch-dashboards[0].requires.ingress.name
    endpoint = module.opensearch-dashboards[0].requires.ingress.endpoint
  }

  application {
    name      = local.ingress_provider.kind == "endpoint" ? local.ingress_provider.name : null
    endpoint  = local.ingress_provider.kind == "endpoint" ? local.ingress_provider.endpoint : null
    offer_url = local.ingress_provider.kind == "offer" ? local.ingress_provider.url : null
  }
}

resource "juju_integration" "traefik_k8s-tls-integration" {
  count      = length(juju_application.traefik-k8s) > 0 ? 1 : 0
  model_uuid = local.main_model_uuid

  application {
    name     = juju_application.traefik-k8s[0].name
    endpoint = "certificates"
  }

  application {
    name      = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.name : null
    endpoint  = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.endpoint : null
    offer_url = local.certificates_provider.kind == "offer" ? local.certificates_provider.url : null
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

resource "juju_integration" "grafana_dashboard-opensearch-integration" {
  for_each   = var.grafana_dashboard_integration != null ? local.opensearch_apps : {}
  model_uuid = each.value.model_uuid

  application {
    name      = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.name : null
    endpoint  = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.endpoint : null
    offer_url = var.grafana_dashboard_integration.kind == "offer" ? var.grafana_dashboard_integration.url : null
  }

  application {
    name     = each.value.provides.grafana_dashboard.name
    endpoint = each.value.provides.grafana_dashboard.endpoint
  }

  lifecycle {
    precondition {
      condition     = var.grafana_dashboard_integration.kind == "offer" || each.value.model_uuid == local.main_model_uuid
      error_message = "A grafana_dashboard_integration with kind = \"endpoint\" only works for apps in the main model. Use kind = \"offer\"."
    }
  }
}

resource "juju_integration" "grafana_dashboard-opensearch_dashboards-integration" {
  count      = local.dashboards_enabled && var.grafana_dashboard_integration != null ? 1 : 0
  model_uuid = local.main_model_uuid

  application {
    name      = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.name : null
    endpoint  = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.endpoint : null
    offer_url = var.grafana_dashboard_integration.kind == "offer" ? var.grafana_dashboard_integration.url : null
  }

  application {
    name     = module.opensearch-dashboards[0].provides.grafana_dashboard.name
    endpoint = module.opensearch-dashboards[0].provides.grafana_dashboard.endpoint
  }
}

resource "juju_integration" "logging-opensearch-integration" {
  for_each   = var.logging_integration != null ? local.opensearch_apps : {}
  model_uuid = each.value.model_uuid

  application {
    name      = var.logging_integration.kind == "endpoint" ? var.logging_integration.name : null
    endpoint  = var.logging_integration.kind == "endpoint" ? var.logging_integration.endpoint : null
    offer_url = var.logging_integration.kind == "offer" ? var.logging_integration.url : null
  }

  application {
    name     = each.value.requires.logging.name
    endpoint = each.value.requires.logging.endpoint
  }

  lifecycle {
    precondition {
      condition     = var.logging_integration.kind == "offer" || each.value.model_uuid == local.main_model_uuid
      error_message = "A logging_integration with kind = \"endpoint\" only works for apps in the main model. Use kind = \"offer\"."
    }
  }
}

resource "juju_integration" "logging-opensearch_dashboards-integration" {
  count      = local.dashboards_enabled && var.logging_integration != null ? 1 : 0
  model_uuid = local.main_model_uuid

  application {
    name      = var.logging_integration.kind == "endpoint" ? var.logging_integration.name : null
    endpoint  = var.logging_integration.kind == "endpoint" ? var.logging_integration.endpoint : null
    offer_url = var.logging_integration.kind == "offer" ? var.logging_integration.url : null
  }

  application {
    name     = module.opensearch-dashboards[0].requires.logging.name
    endpoint = module.opensearch-dashboards[0].requires.logging.endpoint
  }
}

resource "juju_integration" "metrics_endpoint-opensearch-integration" {
  for_each   = var.metrics_endpoint_integration != null ? local.opensearch_apps : {}
  model_uuid = each.value.model_uuid

  application {
    name      = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.name : null
    endpoint  = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.endpoint : null
    offer_url = var.metrics_endpoint_integration.kind == "offer" ? var.metrics_endpoint_integration.url : null
  }

  application {
    name     = each.value.provides.metrics_endpoint.name
    endpoint = each.value.provides.metrics_endpoint.endpoint
  }

  lifecycle {
    precondition {
      condition     = var.metrics_endpoint_integration.kind == "offer" || each.value.model_uuid == local.main_model_uuid
      error_message = "A metrics_endpoint_integration with kind = \"endpoint\" only works for apps in the main model. Use kind = \"offer\"."
    }
  }
}

resource "juju_integration" "metrics_endpoint-opensearch_dashboards-integration" {
  count      = local.dashboards_enabled && var.metrics_endpoint_integration != null ? 1 : 0
  model_uuid = local.main_model_uuid

  application {
    name      = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.name : null
    endpoint  = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.endpoint : null
    offer_url = var.metrics_endpoint_integration.kind == "offer" ? var.metrics_endpoint_integration.url : null
  }

  application {
    name     = module.opensearch-dashboards[0].provides.metrics_endpoint.name
    endpoint = module.opensearch-dashboards[0].provides.metrics_endpoint.endpoint
  }
}
