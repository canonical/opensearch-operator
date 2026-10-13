# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_names" {
  description = "Output of all deployed application names."
  value       = { for key, app in local.components : key => app.name }
}

output "metadata" {
  description = "Product deployment metadata."
  value = {
    deployed_at = terraform_data.deployed_at.output
    updated_at  = terraform_data.updated_at.output
  }
}

output "models" {
  description = "Deployed applications."
  value = {
    for uuid in distinct([for app in local.components : app.model_uuid]) : uuid => {
      model_uuid = uuid
      components = { for key, app in local.components : key => app if app.model_uuid == uuid }
    }
  }
}

output "offers" {
  description = "Map of offer URLs."
  value = merge(
    local.main_app.offers,
    local.failover_enabled ? { for key, offer in local.failover_app.offers : "failover_${key}" => offer } : {},
    var.certificates_integration == null ? { certificates = { kind = "offer", url = juju_offer.certificates[0].url } } : {},
  )
}

output "provides" {
  description = "Map of all `provides` endpoints of the main orchestrator."
  value = {
    opensearch_client            = local.main_app.provides.opensearch_client
    opensearch_grafana_dashboard = local.main_app.provides.grafana_dashboard
    opensearch_metrics_endpoint  = local.main_app.provides.metrics_endpoint
  }
}

output "requires" {
  description = "Map of all `requires` endpoints of the main orchestrator."
  value = {
    opensearch_certificates      = local.main_app.requires.certificates
    opensearch_s3_credentials    = local.main_app.requires.s3_credentials
    opensearch_azure_credentials = local.main_app.requires.azure_credentials
    opensearch_gcs_credentials   = local.main_app.requires.gcs_credentials
    opensearch_jwt_configuration = local.main_app.requires.jwt_configuration
    opensearch_logging           = local.main_app.requires.logging
    opensearch_oauth             = local.main_app.requires.oauth
    opensearch_smtp              = local.main_app.requires.smtp
  }
}
