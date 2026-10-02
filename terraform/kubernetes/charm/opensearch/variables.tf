# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "app_name" {
  description = "Application name."
  type        = string
  default     = "opensearch-k8s"
  nullable    = false
}

variable "base" {
  description = "The operating system on which to deploy."
  type        = string
  default     = null
}

variable "channel" {
  description = "Charmhub channel."
  type        = string
  default     = "2/edge"
  nullable    = false
}

variable "config" {
  description = "OpenSearch charm configuration."
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "constraints" {
  description = "Constraints for this application."
  type        = string
  default     = null
}

variable "expose" {
  description = "Expose the application for external access."
  type = list(object({
    cidrs     = optional(string)
    endpoints = optional(string)
    spaces    = optional(string)
  }))
  default  = []
  nullable = false
}

variable "model_uuid" {
  description = "Model UUID"
  type        = string
  nullable    = false
}

variable "offered_endpoints" {
  description = "Endpoints to expose as Juju offers for cross-model integration."
  type        = list(string)
  default     = []
  nullable    = false

  validation {
    condition     = alltrue([for endpoint in var.offered_endpoints : contains(["grafana-dashboard", "metrics-endpoint", "opensearch-client", "peer-cluster-orchestrator"], endpoint)])
    error_message = "offered_endpoints may only contain grafana-dashboard, metrics-endpoint, opensearch-client or peer-cluster-orchestrator."
  }
}

variable "resources" {
  description = "Map of the charm resources (`opensearch-image`). When not set, the image published with the charm revision is used."
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "revision" {
  description = "Charm revision"
  type        = number
  default     = null
}

variable "storage_directives" {
  description = "Map of storage directives for the charm."
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "units" {
  description = "Charm units."
  type        = number
  default     = 1
}
