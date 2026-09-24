# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "apps" {
  description = "Non-orchestrator OpenSearch apps. Defaults to one app with 'data' role."
  type = list(object({
    app_name           = string
    model_uuid         = optional(string)
    config             = optional(map(string), {})
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
  }))
  default = [
    { app_name = "data", config = { roles = "data" } },
  ]
  nullable = false

  validation {
    condition     = length(distinct([for app in var.apps : app.app_name])) == length(var.apps)
    error_message = "App names must be unique."
  }

  validation {
    condition = alltrue([
      for app in var.apps : lookup(app.config, "roles", "") != "" && !contains([for role in split(",", lookup(app.config, "roles", "")) : trimspace(role)], "cluster_manager")
    ])
    error_message = "Apps cannot have a cluster_manager role. Use the optional failover variable to set a failover orchestrator."
  }

  validation {
    condition     = alltrue([for app in var.apps : lookup(app.config, "init_hold", "true") == "true"])
    error_message = "Each app's config.init_hold must be unset or true."
  }
}

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

variable "cluster_name" {
  description = "The cluster name of the fleet."
  type        = string
  default     = "opensearch"
  nullable    = false
}

variable "cos_agent_integrations" {
  description = "Optional same-model COS agent endpoints, keyed by the name of the OpenSearch or OpenSearch Dashboards app to integrate."
  type = map(object({
    name     = string
    endpoint = string
  }))
  default  = {}
  nullable = false
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

variable "failover" {
  description = "Optional failover orchestrator"
  type = object({
    app_name           = optional(string, "failover")
    model_uuid         = optional(string)
    config             = optional(map(string), {})
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
  default = null

  validation {
    condition     = var.failover == null ? true : lookup(var.failover.config, "roles", "") == "" || contains([for role in split(",", lookup(var.failover.config, "roles", "")) : trimspace(role)], "cluster_manager")
    error_message = "The failover roles must be either empty or include cluster_manager."
  }

  validation {
    condition     = var.failover == null ? true : lookup(var.failover.config, "init_hold", "true") == "true"
    error_message = "failover.config.init_hold must be unset or true."
  }
}

variable "main" {
  description = "Main orchestrator app definition. Default role is cluster_manager."
  type = object({
    app_name           = optional(string, "main")
    model_uuid         = string
    config             = optional(map(string), {})
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

  validation {
    condition     = lookup(var.main.config, "roles", "") == "" || contains([for role in split(",", lookup(var.main.config, "roles", "")) : trimspace(role)], "cluster_manager")
    error_message = "The main roles must be either empty or include cluster_manager."
  }

  validation {
    condition     = lookup(var.main.config, "init_hold", "false") == "false"
    error_message = "main.config.init_hold must be unset or false."
  }
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
