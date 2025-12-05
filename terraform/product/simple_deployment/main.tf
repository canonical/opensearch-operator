# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

#--------------------------------------------------------
# 1. DEPLOYMENTS
#--------------------------------------------------------

# main opensearch app
module "opensearch" {
  source = "../../charm/simple_deployment"

  channel  = var.opensearch.channel
  revision = var.opensearch.revision
  base     = var.opensearch.base

  app_name          = var.opensearch.app_name
  units             = var.opensearch.units
  config            = merge(var.opensearch.config, { "init_hold" : "false" })
  model_uuid        = var.opensearch.model_uuid
  constraints       = var.opensearch.constraints
  storage           = var.opensearch.storage
  endpoint_bindings = var.opensearch.endpoint_bindings
  machines          = var.opensearch.machines
  expose            = var.opensearch.expose

  self-signed-certificates = var.self-signed-certificates
}

# OpenSearch dashboards
module "opensearch-dashboards" {
  source     = "git::https://github.com/canonical/opensearch-dashboards-operator//terraform?ref=2/edge"
  model_uuid = var.opensearch.model_uuid

  channel  = var.opensearch-dashboards.channel
  revision = var.opensearch-dashboards.revision
  base     = var.opensearch-dashboards.base

  app_name          = var.opensearch-dashboards.app_name
  units             = var.opensearch-dashboards.units
  config            = var.opensearch-dashboards.config
  constraints       = var.opensearch-dashboards.constraints
  endpoint_bindings = var.opensearch-dashboards.endpoint_bindings
  machines          = var.opensearch-dashboards.machines
  expose            = var.opensearch-dashboards.expose
}

# Integrator apps and grafana-agent
resource "juju_application" "data-integrator" {
  charm {
    name     = "data-integrator"
    channel  = var.data-integrator.channel
    revision = var.data-integrator.revision
    base     = var.data-integrator.base
  }
  model_uuid = var.opensearch.model_uuid
  config     = var.data-integrator.config

  constraints = var.data-integrator.constraints
  machines    = (var.data-integrator.machines == null || length(var.data-integrator.machines) == 0) ? null : var.data-integrator.machines
}

resource "juju_application" "grafana-agent" {
  charm {
    name     = "grafana-agent"
    channel  = var.grafana-agent.channel
    revision = var.grafana-agent.revision
    base     = var.grafana-agent.base
  }
  model_uuid = var.opensearch.model_uuid
  config     = var.grafana-agent.config
}

resource "juju_application" "backups-integrator" {
  charm {
    name     = "${var.backups-integrator.storage_type}-integrator"
    channel  = var.backups-integrator.channel
    revision = var.backups-integrator.revision
    base     = var.backups-integrator.base
  }
  model_uuid = var.opensearch.model_uuid
  config     = var.backups-integrator.config

  constraints = var.backups-integrator.constraints
  machines    = (var.backups-integrator.machines == null || length(var.backups-integrator.machines) == 0) ? null : var.backups-integrator.machines
}


#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

# Integrations
resource "juju_integration" "opensearch_dashboards-tls-integration" {
  for_each = var.opensearch-dashboards.tls ? { "integrate" = true } : {}

  model_uuid = var.opensearch.model_uuid

  application {
    name = var.opensearch-dashboards.app_name
  }

  application {
    name = module.opensearch.app_names["self-signed-certificates"]
  }

  depends_on = [
    module.opensearch,
    module.opensearch-dashboards,
  ]
}

resource "juju_integration" "opensearch_dashboards-opensearch-integration" {
  model_uuid = var.opensearch.model_uuid

  application {
    name = var.opensearch-dashboards.app_name
  }

  application {
    name = var.opensearch.app_name
  }

  depends_on = [
    module.opensearch,
    module.opensearch-dashboards,
  ]
}

resource "juju_integration" "backups_integrator-opensearch-integration" {
  model_uuid = var.opensearch.model_uuid

  application {
    name = juju_application.backups-integrator.name
  }

  application {
    name = var.opensearch.app_name
  }

  depends_on = [
    module.opensearch,
    juju_application.backups-integrator,
  ]
}

resource "juju_integration" "data_integrator-opensearch-integration" {
  model_uuid = var.opensearch.model_uuid

  application {
    name = juju_application.data-integrator.name
  }

  application {
    name = var.opensearch.app_name
  }

  depends_on = [
    module.opensearch,
    juju_application.data-integrator,
  ]
}

resource "juju_integration" "grafana_agent-opensearch-integration" {
  model_uuid = var.opensearch.model_uuid

  application {
    name = juju_application.grafana-agent.name
  }

  application {
    name = var.opensearch.app_name
  }

  depends_on = [
    module.opensearch,
    juju_application.grafana-agent,
  ]
}

resource "juju_integration" "grafana_agent-opensearch_dashboards-integration" {
  model_uuid = var.opensearch.model_uuid

  application {
    name = juju_application.grafana-agent.name
  }

  application {
    name = var.opensearch-dashboards.app_name
  }

  depends_on = [
    module.opensearch-dashboards,
    juju_application.grafana-agent,
  ]
}
