# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


# integration endpoints
output "requires" {
  description = "Map of all \"requires\" endpoints"
  value = {
    peer_cluster   = "opensearch-client"
    certificates   = "certificates"
    s3_credentials = "s3-credentials"
  }
}

output "provides" {
  description = "Map of all \"provides\" endpoints"
  value = {
    peer_cluster_orchestrator = "peer-cluster-orchestrator"
    opensearch_client         = "opensearch-client"
    cos_agent                 = "cos-agent"
  }
}

output "certificates_offer_url" {
  description = "Offer URL for TLS provider"
  value       = try(juju_offer.self_signed_certificates-offer["offered"].url, null)
}

output "peer_cluster_orchestrator_main_offer_url" {
  description = "Offer URL for Main Peer cluster orchestrator"
  value       = try(juju_offer.opensearch_main-offer["offered"].url, null)
}

output "peer_cluster_orchestrator_failover_offer_url" {
  description = "Offer URL for Failover Peer cluster orchestrator"
  value       = try(juju_offer.opensearch_failover-offer["offered"].url, null)
}
