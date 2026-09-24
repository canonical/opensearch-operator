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
  storage_directives = var.opensearch.storage_directives
  endpoint_bindings  = var.opensearch.endpoint_bindings
  machines           = var.opensearch.machines
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
  machines    = length(var.self-signed-certificates.machines) > 0 ? var.self-signed-certificates.machines : null
  units       = length(var.self-signed-certificates.machines) > 0 ? null : var.self-signed-certificates.units
}

# OpenSearch dashboards
module "opensearch-dashboards" {
  count  = local.dashboards_enabled ? 1 : 0
  source = "git::https://github.com/canonical/opensearch-dashboards-operator.git//terraform/machine/charm/opensearch_dashboards?ref=c2c180d203f95af2a7c22173f3412a0c617ffc7d"

  app_name          = var.opensearch-dashboards.app_name
  base              = var.opensearch-dashboards.base
  channel           = var.opensearch-dashboards.channel
  config            = var.opensearch-dashboards.config
  constraints       = var.opensearch-dashboards.constraints
  endpoint_bindings = var.opensearch-dashboards.endpoint_bindings
  expose            = var.opensearch-dashboards.expose
  machines          = var.opensearch-dashboards.machines
  model_uuid        = var.opensearch.model_uuid
  revision          = var.opensearch-dashboards.revision
  units             = var.opensearch-dashboards.units
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
  machines    = length(var.data-integrator.machines) > 0 ? var.data-integrator.machines : null
  units       = length(var.data-integrator.machines) > 0 ? null : 1
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
    var.cos_agent_integration,
    var.data-integrator,
    var.opensearch,
    var.opensearch-dashboards,
    var.self-signed-certificates,
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
