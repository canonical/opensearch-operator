# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.opensearch.name
}

# Required integration endpoints

output "certificates_endpoint" {
  description = "Name of the endpoint used to integrate with the TLS certificates provider."
  value       = "certificates"
}

output "peer_cluster_endpoint" {
  description = "Name of the endpoint used to connect with the peer-cluster."
  value       = "peer-cluster"
}

output "s3_credentials_endpoint" {
  description = "Name of the endpoint used to provide s3 support for backups."
  value       = "s3-credentials"
}

# Provided integration endpoints

output "peer_cluster_orchestrator_endpoint" {
  description = "Name of the peer cluster orchestrator endpoint."
  value       = "peer-cluster-orchestrator"
}

output "opensearch_client_endpoint" {
  description = "Name of the endpoint opensearch-client endpoint."
  value       = "opensearch-client"
}

output "cos_agent_endpoint" {
  description = "Name of the endpoint used to provide COS agent integration."
  value       = "cos-agent-endpoint"
}
