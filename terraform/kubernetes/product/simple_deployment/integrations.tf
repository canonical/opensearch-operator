# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

# Integrations
resource "juju_integration" "opensearch-tls-integration" {
  model_uuid = var.opensearch.model_uuid

  application {
    name     = module.opensearch.requires.certificates.name
    endpoint = module.opensearch.requires.certificates.endpoint
  }

  application {
    name      = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.name : null
    endpoint  = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.endpoint : null
    offer_url = local.certificates_provider.kind == "offer" ? local.certificates_provider.url : null
  }
}

resource "juju_integration" "opensearch_dashboards-tls-integration" {
  count      = try(var.opensearch-dashboards.tls, false) ? 1 : 0
  model_uuid = var.opensearch.model_uuid

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

resource "juju_integration" "opensearch_dashboards-opensearch-integration" {
  count      = local.dashboards_enabled ? 1 : 0
  model_uuid = var.opensearch.model_uuid

  application {
    name     = module.opensearch-dashboards[0].requires.opensearch_client.name
    endpoint = module.opensearch-dashboards[0].requires.opensearch_client.endpoint
  }

  application {
    name     = module.opensearch.provides.opensearch_client.name
    endpoint = module.opensearch.provides.opensearch_client.endpoint
  }
}

resource "juju_integration" "opensearch_dashboards-ingress-integration" {
  count      = local.dashboards_enabled ? 1 : 0
  model_uuid = var.opensearch.model_uuid

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
  model_uuid = var.opensearch.model_uuid

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
  model_uuid = var.opensearch.model_uuid

  application {
    name      = local.backups_is_cross_model ? null : juju_application.backups-integrator[0].name
    endpoint  = local.backups_is_cross_model ? null : local.backups_settings[var.backups-integrator.storage_type].endpoint
    offer_url = local.backups_is_cross_model ? juju_offer.backups_credentials[0].url : null
  }

  application {
    name     = module.opensearch.application.name
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
    name      = local.data_integrator_is_cross_model ? null : module.opensearch.provides.opensearch_client.name
    endpoint  = local.data_integrator_is_cross_model ? null : module.opensearch.provides.opensearch_client.endpoint
    offer_url = local.data_integrator_is_cross_model ? juju_offer.opensearch_client[0].url : null
  }
}

resource "juju_integration" "grafana_dashboard-opensearch-integration" {
  count      = var.grafana_dashboard_integration != null ? 1 : 0
  model_uuid = var.opensearch.model_uuid

  application {
    name      = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.name : null
    endpoint  = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.endpoint : null
    offer_url = var.grafana_dashboard_integration.kind == "offer" ? var.grafana_dashboard_integration.url : null
  }

  application {
    name     = module.opensearch.provides.grafana_dashboard.name
    endpoint = module.opensearch.provides.grafana_dashboard.endpoint
  }
}

resource "juju_integration" "grafana_dashboard-opensearch_dashboards-integration" {
  count      = local.dashboards_enabled && var.grafana_dashboard_integration != null ? 1 : 0
  model_uuid = var.opensearch.model_uuid

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
  count      = var.logging_integration != null ? 1 : 0
  model_uuid = var.opensearch.model_uuid

  application {
    name      = var.logging_integration.kind == "endpoint" ? var.logging_integration.name : null
    endpoint  = var.logging_integration.kind == "endpoint" ? var.logging_integration.endpoint : null
    offer_url = var.logging_integration.kind == "offer" ? var.logging_integration.url : null
  }

  application {
    name     = module.opensearch.requires.logging.name
    endpoint = module.opensearch.requires.logging.endpoint
  }
}

resource "juju_integration" "logging-opensearch_dashboards-integration" {
  count      = local.dashboards_enabled && var.logging_integration != null ? 1 : 0
  model_uuid = var.opensearch.model_uuid

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
  count      = var.metrics_endpoint_integration != null ? 1 : 0
  model_uuid = var.opensearch.model_uuid

  application {
    name      = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.name : null
    endpoint  = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.endpoint : null
    offer_url = var.metrics_endpoint_integration.kind == "offer" ? var.metrics_endpoint_integration.url : null
  }

  application {
    name     = module.opensearch.provides.metrics_endpoint.name
    endpoint = module.opensearch.provides.metrics_endpoint.endpoint
  }
}

resource "juju_integration" "metrics_endpoint-opensearch_dashboards-integration" {
  count      = local.dashboards_enabled && var.metrics_endpoint_integration != null ? 1 : 0
  model_uuid = var.opensearch.model_uuid

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
