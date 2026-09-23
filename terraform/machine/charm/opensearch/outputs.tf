output "application" {
  description = "The deployed OpenSearch application object."
  value       = juju_application.opensearch
}

output "offers" {
  description = "No offers are exposed by this charm."
  value       = {}
}

output "provides" {
  description = "Map of all 'provides' endpoints."
  value = {
    cos_agent = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "cos-agent"
    }
    opensearch_client = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "opensearch-client"
    }
    peer_cluster_orchestrator = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "peer-cluster-orchestrator"
    }
  }
}

output "requires" {
  description = "Map of all 'requires' endpoints."
  value = {
    azure_credentials = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "azure-credentials"
    }
    certificates = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "certificates"
    }
    gcs_credentials = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "gcs-credentials"
    }
    jwt_configuration = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "jwt-configuration"
    }
    oauth = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "oauth"
    }
    peer_cluster = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "peer-cluster"
    }
    s3_credentials = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "s3-credentials"
    }
    smtp = {
      kind     = "endpoint"
      name     = juju_application.opensearch.name
      endpoint = "smtp"
    }
  }
}
