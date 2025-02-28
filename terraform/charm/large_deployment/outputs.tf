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

output "app_names" {
  description = "Output of all deployed application names."
  value = {
    opensearch_main     = module.opensearch_main.app_names["opensearch"]
    opensearch_failover = module.opensearch_failover.app_names["opensearch"]
    opensearch_apps = [
      for app_module in module.opensearch_non_orchestrator_apps :
      app_module.app_names["opensearch"]
    ]
    self-signed-certificates = module.opensearch_main.app_names["self-signed-certificates"]
  }
}

output "offers" {
  description = "List of offers URLs."
  value = {
    opensearch_main     = try(juju_offer.opensearch_main-offer["offered"].url, null)
    opensearch_failover = try(juju_offer.opensearch_failover-offer["offered"].url, null)
    certificates        = try(juju_offer.self_signed_certificates-offer["offered"].url, null)
  }
}
