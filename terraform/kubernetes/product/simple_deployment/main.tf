# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

#--------------------------------------------------------
# 1. DEPLOYMENTS
#--------------------------------------------------------

# main opensearch app
module "opensearch" {
  source = "../../charm/opensearch"

  channel  = var.opensearch.channel
  revision = var.opensearch.revision
  base     = var.opensearch.base

  app_name           = var.opensearch.app_name
  units              = var.opensearch.units
  config             = merge(var.opensearch.config, { "init_hold" : "false" })
  model_uuid         = var.opensearch.model_uuid
  constraints        = var.opensearch.constraints
  resources          = var.opensearch.resources
  storage_directives = var.opensearch.storage_directives
  expose             = var.opensearch.expose
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
  model_uuid = var.opensearch.model_uuid
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
  model_uuid  = var.opensearch.model_uuid
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
  model_uuid = var.opensearch.model_uuid
  config     = var.traefik-k8s.config

  constraints = var.traefik-k8s.constraints
  trust       = true
  units       = var.traefik-k8s.units
}

# Integrator apps
resource "juju_application" "data-integrator" {
  count = local.data_integrator_enabled ? 1 : 0

  charm {
    name     = "data-integrator"
    channel  = var.data-integrator.channel
    revision = var.data-integrator.revision
    base     = var.data-integrator.base
  }
  model_uuid = local.data_integrator_model_uuid
  config     = var.data-integrator.config

  constraints = var.data-integrator.constraints
  units       = 1
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

resource "terraform_data" "deployed_at" {
  input = timestamp()

  lifecycle {
    ignore_changes = [input]
  }
}

resource "terraform_data" "updated_at" {
  input = timestamp()
  triggers_replace = sha256(jsonencode([
    var.backups-integrator,
    var.certificates_integration,
    var.data-integrator,
    var.grafana_dashboard_integration,
    var.ingress_integration,
    var.logging_integration,
    var.metrics_endpoint_integration,
    var.opensearch,
    var.opensearch-dashboards,
    var.self-signed-certificates,
    var.traefik-k8s,
  ]))

  lifecycle {
    ignore_changes = [input]
  }
}

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
    name                = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.name : null
    endpoint            = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.endpoint : null
    offer_url           = local.certificates_provider.kind == "offer" ? local.certificates_provider.url : null
    offering_controller = local.certificates_provider.kind == "offer" ? local.certificates_provider.controller : null
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
    name                = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.name : null
    endpoint            = local.certificates_provider.kind == "endpoint" ? local.certificates_provider.endpoint : null
    offer_url           = local.certificates_provider.kind == "offer" ? local.certificates_provider.url : null
    offering_controller = local.certificates_provider.kind == "offer" ? local.certificates_provider.controller : null
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
    name                = local.ingress_provider.kind == "endpoint" ? local.ingress_provider.name : null
    endpoint            = local.ingress_provider.kind == "endpoint" ? local.ingress_provider.endpoint : null
    offer_url           = local.ingress_provider.kind == "offer" ? local.ingress_provider.url : null
    offering_controller = local.ingress_provider.kind == "offer" ? local.ingress_provider.controller : null
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
    name     = juju_application.data-integrator[0].name
    endpoint = "opensearch"
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
    name                = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.name : null
    endpoint            = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.endpoint : null
    offer_url           = var.grafana_dashboard_integration.kind == "offer" ? var.grafana_dashboard_integration.url : null
    offering_controller = var.grafana_dashboard_integration.kind == "offer" ? var.grafana_dashboard_integration.controller : null
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
    name                = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.name : null
    endpoint            = var.grafana_dashboard_integration.kind == "endpoint" ? var.grafana_dashboard_integration.endpoint : null
    offer_url           = var.grafana_dashboard_integration.kind == "offer" ? var.grafana_dashboard_integration.url : null
    offering_controller = var.grafana_dashboard_integration.kind == "offer" ? var.grafana_dashboard_integration.controller : null
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
    name                = var.logging_integration.kind == "endpoint" ? var.logging_integration.name : null
    endpoint            = var.logging_integration.kind == "endpoint" ? var.logging_integration.endpoint : null
    offer_url           = var.logging_integration.kind == "offer" ? var.logging_integration.url : null
    offering_controller = var.logging_integration.kind == "offer" ? var.logging_integration.controller : null
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
    name                = var.logging_integration.kind == "endpoint" ? var.logging_integration.name : null
    endpoint            = var.logging_integration.kind == "endpoint" ? var.logging_integration.endpoint : null
    offer_url           = var.logging_integration.kind == "offer" ? var.logging_integration.url : null
    offering_controller = var.logging_integration.kind == "offer" ? var.logging_integration.controller : null
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
    name                = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.name : null
    endpoint            = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.endpoint : null
    offer_url           = var.metrics_endpoint_integration.kind == "offer" ? var.metrics_endpoint_integration.url : null
    offering_controller = var.metrics_endpoint_integration.kind == "offer" ? var.metrics_endpoint_integration.controller : null
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
    name                = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.name : null
    endpoint            = var.metrics_endpoint_integration.kind == "endpoint" ? var.metrics_endpoint_integration.endpoint : null
    offer_url           = var.metrics_endpoint_integration.kind == "offer" ? var.metrics_endpoint_integration.url : null
    offering_controller = var.metrics_endpoint_integration.kind == "offer" ? var.metrics_endpoint_integration.controller : null
  }

  application {
    name     = module.opensearch-dashboards[0].provides.metrics_endpoint.name
    endpoint = module.opensearch-dashboards[0].provides.metrics_endpoint.endpoint
  }
}
