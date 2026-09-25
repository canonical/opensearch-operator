# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

output "application" {
  description = "The deployed OpenSearch application object."
  value       = juju_application.opensearch_k8s
}

output "offers" {
  description = "Map of all offers exposed by this application."
  value = {
    for endpoint, offer in juju_offer.offered_endpoints : replace(endpoint, "-", "_") => {
      kind = "offer"
      url  = offer.url
    }
  }
}

output "provides" {
  description = "Map of all 'provides' endpoints."
  value = {
    grafana_dashboard = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "grafana-dashboard"
    }
    metrics_endpoint = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "metrics-endpoint"
    }
    opensearch_client = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "opensearch-client"
    }
    peer_cluster_orchestrator = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "peer-cluster-orchestrator"
    }
  }
}

output "requires" {
  description = "Map of all 'requires' endpoints."
  value = {
    azure_credentials = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "azure-credentials"
    }
    certificates = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "certificates"
    }
    gcs_credentials = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "gcs-credentials"
    }
    jwt_configuration = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "jwt-configuration"
    }
    logging = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "logging"
    }
    oauth = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "oauth"
    }
    peer_cluster = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "peer-cluster"
    }
    s3_credentials = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "s3-credentials"
    }
    smtp = {
      kind     = "endpoint"
      name     = juju_application.opensearch_k8s.name
      endpoint = "smtp"
    }
  }
}
