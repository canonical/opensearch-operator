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
