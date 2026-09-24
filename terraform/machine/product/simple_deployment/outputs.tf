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
  description = "Deployed applications"
  value = {
    for uuid in distinct([for app in local.components : app.model_uuid]) : uuid => {
      model_uuid = uuid
      components = { for key, app in local.components : key => app if app.model_uuid == uuid }
    }
  }
}

output "offers" {
  description = "List of offers URLs."
  value = {
    opensearch_client = try({
      kind = "offer"
      name = module.opensearch.application.name
      url  = juju_offer.opensearch_client[0].url
    }, null)
    backups_integrator_credentials = try({
      kind = "offer"
      name = juju_application.backups-integrator[0].name
      url  = juju_offer.backups_credentials[0].url
    }, null)
  }
}

output "provides" {
  description = "Map of all 'provides' endpoints"
  value = {
    opensearch_client    = module.opensearch.provides.opensearch_client
    opensearch_cos_agent = module.opensearch.provides.cos_agent
  }
}

output "requires" {
  description = "Map of all 'requires' endpoints"
  value = {
    opensearch_certificates      = module.opensearch.requires.certificates
    opensearch_s3_credentials    = module.opensearch.requires.s3_credentials
    opensearch_azure_credentials = module.opensearch.requires.azure_credentials
    opensearch_gcs_credentials   = module.opensearch.requires.gcs_credentials
    opensearch_jwt_configuration = module.opensearch.requires.jwt_configuration
    opensearch_oauth             = module.opensearch.requires.oauth
    opensearch_smtp              = module.opensearch.requires.smtp
  }
}
