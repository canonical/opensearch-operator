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

resource "juju_integration" "backups_integrator-opensearch-integration" {
  count      = local.backups_enabled || var.backups_integration != null ? 1 : 0
  model_uuid = var.opensearch.model_uuid

  application {
    name      = local.backups_provider.kind == "endpoint" ? local.backups_provider.name : null
    endpoint  = local.backups_provider.kind == "endpoint" ? local.backups_provider.endpoint : null
    offer_url = local.backups_provider.kind == "offer" ? local.backups_provider.url : null
  }

  application {
    name     = module.opensearch.application.name
    endpoint = local.backups_settings[local.backups_provider.storage_type].endpoint
  }
}

resource "juju_integration" "data_integrator-opensearch-integration" {
  count      = local.data_integrator_enabled ? 1 : 0
  model_uuid = var.opensearch.model_uuid

  application {
    name     = module.data-integrator[0].requires.opensearch.name
    endpoint = module.data-integrator[0].requires.opensearch.endpoint
  }

  application {
    name     = module.opensearch.provides.opensearch_client.name
    endpoint = module.opensearch.provides.opensearch_client.endpoint
  }
}

resource "juju_integration" "cos_agent-opensearch-integration" {
  count      = var.cos_agent_integration != null ? 1 : 0
  model_uuid = var.opensearch.model_uuid

  application {
    name     = var.cos_agent_integration.name
    endpoint = var.cos_agent_integration.endpoint
  }

  application {
    name     = module.opensearch.provides.cos_agent.name
    endpoint = module.opensearch.provides.cos_agent.endpoint
  }
}

resource "juju_integration" "cos_agent-opensearch_dashboards-integration" {
  count      = local.dashboards_enabled && var.cos_agent_integration != null ? 1 : 0
  model_uuid = var.opensearch.model_uuid

  application {
    name     = var.cos_agent_integration.name
    endpoint = var.cos_agent_integration.endpoint
  }

  application {
    name     = module.opensearch-dashboards[0].provides.cos_agent.name
    endpoint = module.opensearch-dashboards[0].provides.cos_agent.endpoint
  }
}
