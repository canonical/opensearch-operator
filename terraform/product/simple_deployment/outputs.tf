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
  value = merge(
    module.opensearch.app_names,
    {
      "opensearch-dashboards" : module.opensearch-dashboards.app_names["opensearch-dashboards"]
      "data-integrator" : juju_application.data-integrator.name,
      "backups-integrator" : juju_application.backups-integrator.name,
      "grafana-agent" : juju_application.grafana-agent.name
    }
  )
}

output "offers" {
  description = "List of offers URLs."
  value       = {}
}
