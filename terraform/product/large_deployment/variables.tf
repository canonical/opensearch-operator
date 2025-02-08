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
    model             = string
    config            = optional(map(string), {})
    channel           = optional(string, "2/stable")
    base              = optional(string, "ubuntu@22.04")
    revision          = optional(string, null)
    units             = optional(number, 3)
    constraints       = optional(string, "arch=amd64")
    machines          = optional(list(string), [])
    storage           = optional(map(string), {})
    endpoint_bindings = optional(map(string), {})
  })
}

variable "failover" {
  description = "Failover orchestrator app definition"
  type = object({
    app_name          = string
    model             = string
    config            = optional(map(string), { "init_hold" : "true" })
    channel           = optional(string, "2/stable")
    base              = optional(string, "ubuntu@22.04")
    revision          = optional(string, null)
    units             = optional(number, 3)
    constraints       = optional(string, "arch=amd64")
    machines          = optional(list(string), [])
    storage           = optional(map(string), {})
    endpoint_bindings = optional(map(string), {})
  })
  default = null
}

variable "apps" {
  description = "Non orchestrator apps (e.g: ml, data.hot etc.)"
  type = list(object({
    app_name          = string
    model             = string
    config            = optional(map(string), { "init_hold" : "true" })
    channel           = optional(string, "2/stable")
    base              = optional(string, "ubuntu@22.04")
    revision          = optional(string, null)
    units             = optional(number, 3)
    constraints       = optional(string, "arch=amd64")
    machines          = optional(list(string), [])
    storage           = optional(map(string), {})
    endpoint_bindings = optional(map(string), {})
  }))
  default = null
}

# Integrators
variable "backups-integrator" {
  description = "Configuration for the backup integrator"
  type = object({
    storage_type = optional(string, "s3")
    config       = map(string)
  })

  validation {
    condition     = contains(["s3", "azure"], var.backups-integrator.storage_type)
    error_message = "backup-integrator allows one of the values: 's3', 'azure' for storage_type."
  }
}

variable "data-integrator" {
  description = "Configuration for the data-integrator"
  type        = map(string)
  default     = { "index-name" : "test", "extra-user-roles" : "admin" }

  validation {
    condition = (
      lookup(var.data-integrator, "index-name", "") != ""
      && contains(["default", "admin"], lookup(var.data-integrator, "extra-user-roles", "admin"))
    )
    error_message = "data-integrator must contain a non-empty 'index-name' and 'extra-user-roles' must be either 'default' or 'admin'."
  }
}
