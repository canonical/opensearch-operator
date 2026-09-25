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
  config             = merge({ "cluster_name" : "opensearch" }, var.opensearch.config)
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
module "data-integrator" {
  count  = local.data_integrator_enabled ? 1 : 0
  source = "git::https://github.com/canonical/data-integrator.git//terraform/charm/data_integrator?ref=rev519"

  base        = var.data-integrator.base
  channel     = var.data-integrator.channel
  config      = var.data-integrator.config
  constraints = var.data-integrator.constraints
  model_uuid  = local.data_integrator_model_uuid
  revision    = var.data-integrator.revision
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
