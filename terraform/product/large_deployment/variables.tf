# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

variable "cluster_name" {
  type        = string
  description = "The cluster name of the fleet."
  default     = "opensearch"
}

variable "main" {
  description = "Main orchestrator app definition"
  type = object({
    app_name          = string
    model_uuid        = string
    config            = optional(map(string), {})
    channel           = optional(string, "2/edge")
    base              = optional(string, "ubuntu@24.04")
    revision          = optional(string, null)
    units             = optional(number, 3)
    constraints       = optional(string, "arch=amd64")
    machines          = optional(list(string), [])
    storage           = optional(map(string), {})
    endpoint_bindings = optional(map(string), {})
    expose            = optional(bool, false)
  })
}

variable "failover" {
  description = "Failover orchestrator app definition"
  type = object({
    app_name          = string
    model_uuid        = string
    config            = optional(map(string), { "init_hold" : "true" })
    channel           = optional(string, "2/edge")
    base              = optional(string, "ubuntu@24.04")
    revision          = optional(string, null)
    units             = optional(number, 3)
    constraints       = optional(string, "arch=amd64")
    machines          = optional(list(string), [])
    storage           = optional(map(string), {})
    endpoint_bindings = optional(map(string), {})
    expose            = optional(bool, false)
  })
  default = null
}

variable "apps" {
  description = "Non orchestrator apps (e.g: ml, data.hot etc.)"
  type = list(object({
    app_name          = string
    model_uuid        = string
    config            = optional(map(string), { "init_hold" : "true" })
    channel           = optional(string, "2/edge")
    base              = optional(string, "ubuntu@24.04")
    revision          = optional(string, null)
    units             = optional(number, 3)
    constraints       = optional(string, "arch=amd64")
    machines          = optional(list(string), [])
    storage           = optional(map(string), {})
    endpoint_bindings = optional(map(string), {})
    expose            = optional(bool, false)
  }))
  default = null
}

variable "opensearch-dashboards" {
  description = "OpenSearch Dashboards app definition"
  type = object({
    app_name          = optional(string, "opensearch-dashboards")
    config            = optional(map(string), {})
    channel           = optional(string, "2/edge")
    base              = optional(string, "ubuntu@24.04")
    revision          = optional(string, null)
    units             = optional(number, 1)
    constraints       = optional(string, "arch=amd64")
    machines          = optional(list(string), [])
    endpoint_bindings = optional(map(string), {})
    tls               = optional(bool, false)
    expose            = optional(bool, false)
  })
  default = {}
}

variable "self-signed-certificates" {
  description = "Configuration for the self-signed-certificates app"
  type = object({
    channel     = optional(string, "1/stable")
    revision    = optional(string, null)
    base        = optional(string, "ubuntu@24.04")
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

variable "grafana-agent" {
  description = "Configuration for the grafana-agent"
  type = object({
    channel     = optional(string, "1/stable")
    revision    = optional(string, null)
    base        = optional(string, "ubuntu@24.04")
    constraints = optional(string, "arch=amd64")
    machines    = optional(list(string), [])
    config      = optional(map(string), {})
  })
  default = {}
}

# Integrators
variable "backups-integrator" {
  description = "Configuration for the backup integrator"
  type = object({
    storage_type = optional(string, "s3")
    config       = map(string)
    channel      = optional(string, "latest/edge")
    base         = optional(string, "ubuntu@22.04")
    revision     = optional(string, null)
    constraints  = optional(string, "arch=amd64")
    machines     = optional(list(string), [])
  })

  validation {
    condition     = contains(["s3", "azure-storage"], var.backups-integrator.storage_type)
    error_message = "backup-integrator allows one of the values: 's3', 'azure' for storage_type."
  }
}

variable "data-integrator" {
  description = "Configuration for the data-integrator"
  type = object({
    config      = optional(map(string), { "index-name" : "test", "extra-user-roles" : "admin" })
    channel     = optional(string, "latest/edge")
    base        = optional(string, "ubuntu@22.04")
    revision    = optional(string, null)
    constraints = optional(string, "arch=amd64")
    machines    = optional(list(string), [])
  })
  default = {}

  validation {
    condition = (
      lookup(var.data-integrator.config, "index-name", "") != ""
      && contains(["default", "admin"], lookup(var.data-integrator.config, "extra-user-roles", "admin"))
    )
    error_message = "data-integrator config must contain a non-empty 'index-name' and 'extra-user-roles' must be either 'default' or 'admin'."
  }
}
