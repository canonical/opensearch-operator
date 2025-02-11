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
  model             = var.opensearch.model
  constraints       = var.opensearch.constraints
  storage           = var.opensearch.storage
  endpoint_bindings = var.opensearch.endpoint_bindings
}

# OpenSearch dashboards
module "opensearch-dashboards" {
  source = "git::https://github.com/canonical/opensearch-dashboards-operator//terraform?ref=2/edge"
  model  = var.opensearch.model
}

# Integrator apps and grafana-agent
resource "juju_application" "data-integrator" {
  charm {
    name    = "data-integrator"
    channel = "latest/stable"
  }
  model  = var.opensearch.model
  config = var.data-integrator
}

resource "juju_application" "grafana-agent" {
  charm {
    name    = "grafana-agent"
    channel = "latest/stable"
  }
  model = var.opensearch.model
}

resource "juju_application" "backups-integrator" {
  charm {
    name    = "${var.backups-integrator.storage_type}-integrator"
    channel = "latest/stable"
  }
  model  = var.opensearch.model
  config = var.backups-integrator.config
}


#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

# Integrations
resource "juju_integration" "opensearch_dashboards-opensearch-integration" {
  model = var.opensearch.model

  application {
    name = module.opensearch-dashboards.app_name
  }

  application {
    name = module.opensearch.app_name
  }

  depends_on = [
    module.opensearch,
    module.opensearch-dashboards,
  ]
}

resource "juju_integration" "backups_integrator-opensearch-integration" {
  model = var.opensearch.model

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
  model = var.opensearch.model

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
  model = var.opensearch.model

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

resource "juju_integration" "grafana_agent-opensearch_dashboards-integration" {
  model = var.opensearch.model

  application {
    name = juju_application.grafana-agent.name
  }

  application {
    name = module.opensearch-dashboards.app_name
  }

  depends_on = [
    module.opensearch-dashboards,
    juju_application.grafana-agent,
  ]
}
