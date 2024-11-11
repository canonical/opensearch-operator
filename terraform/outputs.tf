output "vpc" {
  description = "VPC object copied from variable to the next stage"
  value       = juju_application.opensearch.placement
}