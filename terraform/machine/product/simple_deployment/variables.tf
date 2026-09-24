# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "backups-integrator" {
  description = "Configuration for the optional backup integrator"
  type = object({
    model_uuid   = optional(string)
    storage_type = optional(string, "s3")
    config       = optional(map(string), {})
    channel      = optional(string)
    base         = optional(string)
    revision     = optional(number)
    constraints  = optional(string, "arch=amd64")
    machines     = optional(list(string), [])
  })

  default = null

  validation {
    condition     = var.backups-integrator == null ? true : contains(["s3", "azure-storage", "gcs"], var.backups-integrator.storage_type)
    error_message = "storage_type must be 's3', 'azure-storage' or 'gcs'."
  }

  validation {
    condition     = var.backups-integrator == null ? true : length(var.backups-integrator.machines) <= 1
    error_message = "Machine count should be at most 1"
  }
}

variable "certificates_integration" {
  description = "External TLS endpoint or offer."
  type = object({
    kind     = string
    name     = optional(string)
    endpoint = optional(string)
    url      = optional(string)
  })
  default = null

  validation {
    condition     = var.certificates_integration == null ? true : contains(["endpoint", "offer"], var.certificates_integration.kind)
    error_message = "certificates_integration.kind must be either 'endpoint' or 'offer'."
  }

  validation {
    condition = (
      var.certificates_integration == null ? true :
      var.certificates_integration.kind == "endpoint" ? (
        var.certificates_integration.name != null && var.certificates_integration.name != "" &&
        var.certificates_integration.endpoint != null && var.certificates_integration.endpoint != ""
      ) : true
    )
    error_message = "Both 'name' and 'endpoint' attributes must be provided for an in-model integration."
  }

  validation {
    condition = (
      var.certificates_integration == null ? true :
      var.certificates_integration.kind == "offer" ? (
        var.certificates_integration.url != null && var.certificates_integration.url != ""
      ) : true
    )
    error_message = "The 'url' attribute must be provided for a cross-model integration."
  }
}

variable "cos_agent_integration" {
  description = "COS agent endpoint."
  type = object({
    name     = string
    endpoint = string
  })
  default = null
}

variable "data-integrator" {
  description = "Configuration for the optional data-integrator"
  type = object({
    model_uuid  = optional(string)
    config      = optional(map(string), { "index-name" : "test", "extra-user-roles" : "admin" })
    channel     = optional(string, "latest/stable")
    base        = optional(string, "ubuntu@22.04")
    revision    = optional(number)
    constraints = optional(string, "arch=amd64")
    machines    = optional(list(string), [])
  })
  default = null

  validation {
    condition = var.data-integrator == null ? true : (
      lookup(var.data-integrator.config, "index-name", "") != ""
      && contains(["default", "admin"], lookup(var.data-integrator.config, "extra-user-roles", "admin"))
    )
    error_message = "data-integrator config must contain a non-empty 'index-name' and 'extra-user-roles' must be either 'default' or 'admin'."
  }

  validation {
    condition     = var.data-integrator == null ? true : length(var.data-integrator.machines) <= 1
    error_message = "Machine count should be at most 1"
  }
}

variable "opensearch" {
  description = "OpenSearch app definition"
  type = object({
    app_name           = optional(string, "opensearch")
    model_uuid         = string
    config             = optional(map(string), { "cluster_name" : "opensearch" })
    channel            = optional(string, "2/edge")
    base               = optional(string, "ubuntu@24.04")
    revision           = optional(number)
    units              = optional(number, 3)
    constraints        = optional(string, "arch=amd64")
    machines           = optional(set(string), [])
    storage_directives = optional(map(string), {})
    endpoint_bindings = optional(set(object({
      space    = string
      endpoint = optional(string)
    })), [])
    expose = optional(list(object({
      cidrs     = optional(string)
      endpoints = optional(string)
      spaces    = optional(string)
    })), [])
  })
}

variable "opensearch-dashboards" {
  description = "Optional OpenSearch Dashboards app definition"
  type = object({
    app_name    = optional(string, "opensearch-dashboards")
    config      = optional(map(string), {})
    channel     = optional(string, "2/edge")
    base        = optional(string, "ubuntu@24.04")
    revision    = optional(number)
    units       = optional(number, 1)
    constraints = optional(string, "arch=amd64")
    machines    = optional(set(string), [])
    endpoint_bindings = optional(set(object({
      space    = string
      endpoint = optional(string)
    })), [])
    tls = optional(bool, false)
    expose = optional(list(object({
      cidrs     = optional(string)
      endpoints = optional(string)
      spaces    = optional(string)
    })), [])
  })
  default = null
}

variable "self-signed-certificates" {
  description = "Configuration for the self-signed-certificates app"
  type = object({
    channel     = optional(string, "1/stable")
    revision    = optional(number)
    base        = optional(string, "ubuntu@24.04")
    units       = optional(number, 1)
    constraints = optional(string, "arch=amd64")
    machines    = optional(list(string), [])
    config      = optional(map(string), { "ca-common-name" : "CA" })
  })
  default = {}

  validation {
    condition     = length(var.self-signed-certificates.machines) <= 1
    error_message = "Machine count should be at most 1"
  }
}
