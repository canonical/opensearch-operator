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

# --------
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
