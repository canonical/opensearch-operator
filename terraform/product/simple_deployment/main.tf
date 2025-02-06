# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# main opensearch app
module "opensearch" {
  source                  = "../../charm/simple_deployment"

  channel                 = var.channel
  revision                = var.revision
  base                    = var.base

  app_name                = var.app_name
  units                   = var.units
  config                  = merge(var.config, {"init_hold": "false"})
  model                   = var.model
  constraints             = var.constraints
  storage                 = var.storage
  endpoint_bindings       = var.endpoint_bindings
}

# Integrator apps and grafana-agent
resource "juju_application" "data-integrator" {
  charm {
    name    = "data-integrator"
    channel = "latest/stable"
  }
  model     = var.model
}

resource "juju_application" "grafana-agent" {
  charm {
    name    = "grafana-agent"
    channel = "latest/stable"
  }
  model     = var.model
}

resource "juju_application" "backups-integrator" {
  charm {
    name    = "${var.backups}-integrator"
    channel = "latest/stable"
  }
  model     = var.model
}

# Integrations
resource "juju_integration" "backups_integrator-opensearch-integration" {
  model = var.model

  application {
    name = juju_application.backups-integrator.name
  }

  application {
    name = module.opensearch.app_name
  }

  depends_on = [
    module.opensearch,
    juju_application.backups-integrator,
  ]
}

resource "juju_integration" "data_integrator-opensearch-integration" {
  model = var.model

  application {
    name = juju_application.data-integrator.name
  }

  application {
    name = module.opensearch.app_name
  }

  depends_on = [
    module.opensearch,
    juju_application.data-integrator,
  ]
}

resource "juju_integration" "grafana_agent-opensearch-integration" {
  model = var.model

  application {
    name = juju_application.grafana-agent.name
  }

  application {
    name = module.opensearch.app_name
  }

  depends_on = [
    module.opensearch,
    juju_application.grafana-agent,
  ]
}
