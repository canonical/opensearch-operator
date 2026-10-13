# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

variable "apps" {
  description = "Non-orchestrator OpenSearch apps. Defaults to one `data` app."
  type = list(object({
    app_name           = string
    model_uuid         = optional(string)
    config             = optional(map(string), {})
    channel            = optional(string, "2/edge")
    base               = optional(string, "ubuntu@24.04")
    revision           = optional(number)
    units              = optional(number, 3)
    constraints        = optional(string, "arch=amd64")
    resources          = optional(map(string), {})
    storage_directives = optional(map(string), {})
    expose = optional(list(object({
      cidrs     = optional(string)
      endpoints = optional(string)
      spaces    = optional(string)
    })), [])
    grafana_dashboard_integration = optional(object({
      kind     = string
      name     = optional(string)
      endpoint = optional(string)
      url      = optional(string)
    }))
    logging_integration = optional(object({
      kind     = string
      name     = optional(string)
      endpoint = optional(string)
      url      = optional(string)
    }))
    metrics_endpoint_integration = optional(object({
      kind     = string
      name     = optional(string)
      endpoint = optional(string)
      url      = optional(string)
    }))
  }))
  default = [
    { app_name = "data", config = { roles = "data" } },
  ]
  nullable = false

  validation {
    condition = length(distinct(concat(
      [var.main.app_name],
      var.failover == null ? [] : [var.failover.app_name],
      [for app in var.apps : app.app_name],
    ))) == length(var.apps) + (var.failover == null ? 1 : 2)
    error_message = "OpenSearch app names must be unique."
  }

  validation {
    condition = var.failover != null || alltrue([
      for app in var.apps : lookup(app.config, "roles", "") != "" && !contains([for role in split(",", lookup(app.config, "roles", "")) : trimspace(role)], "cluster_manager")
    ])
    error_message = "`apps` containing `cluster_manager` role requires `failover` to be set."
  }

  validation {
    condition     = alltrue([for app in var.apps : lookup(app.config, "init_hold", "true") == "true"])
    error_message = "`config.init_hold` in `apps` must be unset or `true`."
  }

  validation {
    condition = anytrue([
      for roles in concat(
        [lookup(var.main.config, "roles", "cluster_manager")],
        var.failover == null ? [] : [lookup(var.failover.config, "roles", "cluster_manager")],
        [for app in var.apps : lookup(app.config, "roles", "")],
      ) : roles == "" || anytrue([for role in split(",", roles) : startswith(trimspace(role), "data")])
    ])
    error_message = "At least one OpenSearch app needs a `data` role."
  }

  validation {
    condition = alltrue(flatten([
      for app in var.apps : [
        for cos in [app.grafana_dashboard_integration, app.logging_integration, app.metrics_endpoint_integration] :
        cos == null ? true :
        cos.kind == "endpoint" ? cos.name != null && cos.name != "" && cos.endpoint != null && cos.endpoint != "" :
        cos.kind == "offer" && cos.url != null && cos.url != ""
      ]
    ]))
    error_message = "COS integrations in `apps` need `name` and `endpoint`, or kind `offer` and `url`."
  }
}

variable "azure_storage_secret_key" {
  description = "Azure Storage account key for `azure-storage-integrator`. Supply through `TF_VAR_azure_storage_secret_key` or `-var`, at plan and at apply."
  type        = string
  sensitive   = true
  ephemeral   = true
  default     = null
}

variable "azure_storage_secret_version" {
  description = "Version of the `azure-storage-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove."
  type        = number
  default     = 0

  validation {
    condition     = var.azure_storage_secret_version == 0 || var.backups_integration != null || try(var.backups.storage_type, null) == "azure-storage"
    error_message = "`azure_storage_secret_version` needs an Azure Storage integrator. Set `backups.storage_type` to `azure-storage`."
  }

  validation {
    condition     = var.azure_storage_secret_version == 0 || var.backups_integration == null
    error_message = "`azure_storage_secret_version` can't be used with `backups_integration`."
  }

  validation {
    condition     = var.azure_storage_secret_version >= 0 && floor(var.azure_storage_secret_version) == var.azure_storage_secret_version
    error_message = "`azure_storage_secret_version` must be a non-negative integer."
  }
}

variable "backups" {
  description = "Configuration for the optional backup integrator."
  type = object({
    storage_type           = optional(string, "s3")
    config                 = optional(map(string), {})
    channel                = optional(string)
    credentials_secret_uri = optional(string)
    base                   = optional(string)
    revision               = optional(number)
    constraints            = optional(string, "arch=amd64")
  })

  default = null

  validation {
    condition     = var.backups == null ? true : contains(["s3", "azure-storage", "gcs"], var.backups.storage_type)
    error_message = "`backups.storage_type` must be `s3`, `azure-storage` or `gcs`."
  }

  validation {
    condition     = var.backups == null ? true : !contains(keys(var.backups.config), "credentials")
    error_message = "Set `backups.credentials_secret_uri` instead of `backups.config.credentials`."
  }

  validation {
    condition     = try(startswith(var.backups.credentials_secret_uri, "secret:"), true)
    error_message = "`backups.credentials_secret_uri` must be a Juju secret URI starting with `secret:`."
  }
}

variable "backups_integration" {
  description = "External backup storage endpoint or offer."
  type = object({
    storage_type = optional(string, "s3")
    kind         = string
    name         = optional(string)
    endpoint     = optional(string)
    url          = optional(string)
  })
  default = null

  validation {
    condition     = var.backups_integration == null ? true : contains(["s3", "azure-storage", "gcs"], var.backups_integration.storage_type)
    error_message = "`backups_integration.storage_type` must be `s3`, `azure-storage` or `gcs`."
  }

  validation {
    condition     = var.backups_integration == null ? true : contains(["endpoint", "offer"], var.backups_integration.kind)
    error_message = "`backups_integration.kind` must be `endpoint` or `offer`."
  }

  validation {
    condition = (
      var.backups_integration == null ? true :
      var.backups_integration.kind == "endpoint" ? (
        var.backups_integration.name != null && var.backups_integration.name != "" &&
        var.backups_integration.endpoint != null && var.backups_integration.endpoint != ""
      ) : true
    )
    error_message = "`backups_integration` with kind `endpoint` needs `name` and `endpoint`."
  }

  validation {
    condition = (
      var.backups_integration == null ? true :
      var.backups_integration.kind == "offer" ? (
        var.backups_integration.url != null && var.backups_integration.url != ""
      ) : true
    )
    error_message = "`backups_integration` with kind `offer` needs `url`."
  }

  validation {
    condition     = var.backups_integration == null || var.backups == null
    error_message = "Set `backups` or `backups_integration`, not both."
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
    error_message = "`certificates_integration.kind` must be `endpoint` or `offer`."
  }

  validation {
    condition = (
      var.certificates_integration == null ? true :
      var.certificates_integration.kind == "endpoint" ? (
        var.certificates_integration.name != null && var.certificates_integration.name != "" &&
        var.certificates_integration.endpoint != null && var.certificates_integration.endpoint != ""
      ) : true
    )
    error_message = "`certificates_integration` with kind `endpoint` needs `name` and `endpoint`."
  }

  validation {
    condition = (
      var.certificates_integration == null ? true :
      var.certificates_integration.kind == "offer" ? (
        var.certificates_integration.url != null && var.certificates_integration.url != ""
      ) : true
    )
    error_message = "`certificates_integration` with kind `offer` needs `url`."
  }

  validation {
    condition     = var.certificates_integration == null ? true : var.certificates_integration.kind == "offer" || local.single_model
    error_message = "`certificates_integration` must be an offer when apps are in other models."
  }
}

variable "cluster_name" {
  description = "Cluster name for all OpenSearch apps."
  type        = string
  default     = "opensearch"
  nullable    = false

  validation {
    condition = alltrue([
      for config in concat(
        [var.main.config],
        var.failover == null ? [] : [var.failover.config],
        [for app in var.apps : app.config],
      ) : lookup(config, "cluster_name", var.cluster_name) == var.cluster_name
    ])
    error_message = "`config.cluster_name` must be unset or equal to `cluster_name`."
  }
}

variable "data_integrator" {
  description = "Configuration for the optional `data-integrator`."
  type = object({
    config      = optional(map(string), { "index-name" : "test", "extra-user-roles" : "admin" })
    channel     = optional(string, "latest/stable")
    base        = optional(string, "ubuntu@22.04")
    revision    = optional(number)
    constraints = optional(string, "arch=amd64")
  })
  default = null

  validation {
    condition = var.data_integrator == null ? true : (
      lookup(var.data_integrator.config, "index-name", "") != ""
      && contains(["default", "admin"], lookup(var.data_integrator.config, "extra-user-roles", "admin"))
    )
    error_message = "`data_integrator.config` needs a non-empty `index-name`, and `extra-user-roles` must be `default` or `admin`."
  }
}

variable "failover" {
  description = "Optional failover orchestrator app definition."
  type = object({
    app_name           = optional(string, "failover")
    model_uuid         = optional(string)
    config             = optional(map(string), {})
    channel            = optional(string, "2/edge")
    base               = optional(string, "ubuntu@24.04")
    revision           = optional(number)
    units              = optional(number, 3)
    constraints        = optional(string, "arch=amd64")
    resources          = optional(map(string), {})
    storage_directives = optional(map(string), {})
    expose = optional(list(object({
      cidrs     = optional(string)
      endpoints = optional(string)
      spaces    = optional(string)
    })), [])
    grafana_dashboard_integration = optional(object({
      kind     = string
      name     = optional(string)
      endpoint = optional(string)
      url      = optional(string)
    }))
    logging_integration = optional(object({
      kind     = string
      name     = optional(string)
      endpoint = optional(string)
      url      = optional(string)
    }))
    metrics_endpoint_integration = optional(object({
      kind     = string
      name     = optional(string)
      endpoint = optional(string)
      url      = optional(string)
    }))
  })
  default = null

  validation {
    condition     = var.failover == null ? true : lookup(var.failover.config, "roles", "") == "" || contains([for role in split(",", lookup(var.failover.config, "roles", "")) : trimspace(role)], "cluster_manager")
    error_message = "`failover.config.roles` must be empty or include `cluster_manager`."
  }

  validation {
    condition     = var.failover == null ? true : lookup(var.failover.config, "init_hold", "true") == "true"
    error_message = "`failover.config.init_hold` must be unset or `true`."
  }

  validation {
    condition = var.failover == null ? true : alltrue([
      for cos in [var.failover.grafana_dashboard_integration, var.failover.logging_integration, var.failover.metrics_endpoint_integration] :
      cos == null ? true :
      cos.kind == "endpoint" ? cos.name != null && cos.name != "" && cos.endpoint != null && cos.endpoint != "" :
      cos.kind == "offer" && cos.url != null && cos.url != ""
    ])
    error_message = "COS integrations in `failover` need `name` and `endpoint`, or kind `offer` and `url`."
  }
}

variable "failover_election_timeout" {
  description = "Wait time in seconds for the main orchestrator to elect `failover`, before relating other cluster-manager apps."
  type        = number
  default     = 1800
}

variable "gcs_secret_key" {
  description = "GCS service-account JSON key for `gcs-integrator`. Supply through `TF_VAR_gcs_secret_key` or `-var`, at plan and at apply."
  type        = string
  sensitive   = true
  ephemeral   = true
  default     = null
}

variable "gcs_secret_version" {
  description = "Version of the `gcs-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove."
  type        = number
  default     = 0

  validation {
    condition     = var.gcs_secret_version == 0 || var.backups_integration != null || try(var.backups.storage_type, null) == "gcs"
    error_message = "`gcs_secret_version` needs a GCS integrator. Set `backups.storage_type` to `gcs`."
  }

  validation {
    condition     = var.gcs_secret_version == 0 || var.backups_integration == null
    error_message = "`gcs_secret_version` can't be used with `backups_integration`."
  }

  validation {
    condition     = var.gcs_secret_version >= 0 && floor(var.gcs_secret_version) == var.gcs_secret_version
    error_message = "`gcs_secret_version` must be a non-negative integer."
  }
}

variable "grafana_dashboard_integration" {
  description = "Optional COS Grafana dashboard endpoint or offer."
  type = object({
    kind     = string
    name     = optional(string)
    endpoint = optional(string)
    url      = optional(string)
  })
  default = null

  validation {
    condition     = var.grafana_dashboard_integration == null ? true : contains(["endpoint", "offer"], var.grafana_dashboard_integration.kind)
    error_message = "`grafana_dashboard_integration.kind` must be `endpoint` or `offer`."
  }

  validation {
    condition = (
      var.grafana_dashboard_integration == null ? true :
      var.grafana_dashboard_integration.kind == "endpoint" ? (
        var.grafana_dashboard_integration.name != null && var.grafana_dashboard_integration.name != "" &&
        var.grafana_dashboard_integration.endpoint != null && var.grafana_dashboard_integration.endpoint != ""
      ) : true
    )
    error_message = "`grafana_dashboard_integration` with kind `endpoint` needs `name` and `endpoint`."
  }

  validation {
    condition = (
      var.grafana_dashboard_integration == null ? true :
      var.grafana_dashboard_integration.kind == "offer" ? (
        var.grafana_dashboard_integration.url != null && var.grafana_dashboard_integration.url != ""
      ) : true
    )
    error_message = "`grafana_dashboard_integration` with kind `offer` needs `url`."
  }

  validation {
    condition = var.grafana_dashboard_integration == null ? true : var.grafana_dashboard_integration.kind == "offer" || alltrue([
      for app in local.opensearch_apps : app.grafana_dashboard_integration != null if !app.in_main_model
    ])
    error_message = "OpenSearch apps outside `main`'s model need their own `grafana_dashboard_integration`."
  }
}

variable "ingress_integration" {
  description = "Ingress endpoint or offer for OpenSearch Dashboards. Required when Dashboards is deployed."
  type = object({
    kind     = string
    name     = optional(string)
    endpoint = optional(string)
    url      = optional(string)
  })
  default = null

  validation {
    condition     = var.ingress_integration == null ? true : contains(["endpoint", "offer"], var.ingress_integration.kind)
    error_message = "`ingress_integration.kind` must be `endpoint` or `offer`."
  }

  validation {
    condition = (
      var.ingress_integration == null ? true :
      var.ingress_integration.kind == "endpoint" ? (
        var.ingress_integration.name != null && var.ingress_integration.name != "" &&
        var.ingress_integration.endpoint != null && var.ingress_integration.endpoint != ""
      ) : true
    )
    error_message = "`ingress_integration` with kind `endpoint` needs `name` and `endpoint`."
  }

  validation {
    condition = (
      var.ingress_integration == null ? true :
      var.ingress_integration.kind == "offer" ? (
        var.ingress_integration.url != null && var.ingress_integration.url != ""
      ) : true
    )
    error_message = "`ingress_integration` with kind `offer` needs `url`."
  }

  validation {
    condition     = var.opensearch_dashboards == null || var.ingress_integration != null
    error_message = "`ingress_integration` is unset. OpenSearch Dashboards requires an ingress provider."
  }
}

variable "logging_integration" {
  description = "Optional COS logging endpoint or offer."
  type = object({
    kind     = string
    name     = optional(string)
    endpoint = optional(string)
    url      = optional(string)
  })
  default = null

  validation {
    condition     = var.logging_integration == null ? true : contains(["endpoint", "offer"], var.logging_integration.kind)
    error_message = "`logging_integration.kind` must be `endpoint` or `offer`."
  }

  validation {
    condition = (
      var.logging_integration == null ? true :
      var.logging_integration.kind == "endpoint" ? (
        var.logging_integration.name != null && var.logging_integration.name != "" &&
        var.logging_integration.endpoint != null && var.logging_integration.endpoint != ""
      ) : true
    )
    error_message = "`logging_integration` with kind `endpoint` needs `name` and `endpoint`."
  }

  validation {
    condition = (
      var.logging_integration == null ? true :
      var.logging_integration.kind == "offer" ? (
        var.logging_integration.url != null && var.logging_integration.url != ""
      ) : true
    )
    error_message = "`logging_integration` with kind `offer` needs `url`."
  }

  validation {
    condition = var.logging_integration == null ? true : var.logging_integration.kind == "offer" || alltrue([
      for app in local.opensearch_apps : app.logging_integration != null if !app.in_main_model
    ])
    error_message = "OpenSearch apps outside `main`'s model need their own `logging_integration`."
  }
}

variable "main" {
  description = "Main orchestrator app definition."
  type = object({
    app_name           = optional(string, "main")
    model_uuid         = string
    config             = optional(map(string), {})
    channel            = optional(string, "2/edge")
    base               = optional(string, "ubuntu@24.04")
    revision           = optional(number)
    units              = optional(number, 3)
    constraints        = optional(string, "arch=amd64")
    resources          = optional(map(string), {})
    storage_directives = optional(map(string), {})
    expose = optional(list(object({
      cidrs     = optional(string)
      endpoints = optional(string)
      spaces    = optional(string)
    })), [])
  })

  validation {
    condition     = lookup(var.main.config, "roles", "") == "" || contains([for role in split(",", lookup(var.main.config, "roles", "")) : trimspace(role)], "cluster_manager")
    error_message = "`main.config.roles` must be empty or include `cluster_manager`."
  }

  validation {
    condition     = lookup(var.main.config, "init_hold", "false") == "false"
    error_message = "`main.config.init_hold` must be unset or `false`."
  }
}

variable "metrics_endpoint_integration" {
  description = "Optional COS metrics endpoint or offer."
  type = object({
    kind     = string
    name     = optional(string)
    endpoint = optional(string)
    url      = optional(string)
  })
  default = null

  validation {
    condition     = var.metrics_endpoint_integration == null ? true : contains(["endpoint", "offer"], var.metrics_endpoint_integration.kind)
    error_message = "`metrics_endpoint_integration.kind` must be `endpoint` or `offer`."
  }

  validation {
    condition = (
      var.metrics_endpoint_integration == null ? true :
      var.metrics_endpoint_integration.kind == "endpoint" ? (
        var.metrics_endpoint_integration.name != null && var.metrics_endpoint_integration.name != "" &&
        var.metrics_endpoint_integration.endpoint != null && var.metrics_endpoint_integration.endpoint != ""
      ) : true
    )
    error_message = "`metrics_endpoint_integration` with kind `endpoint` needs `name` and `endpoint`."
  }

  validation {
    condition = (
      var.metrics_endpoint_integration == null ? true :
      var.metrics_endpoint_integration.kind == "offer" ? (
        var.metrics_endpoint_integration.url != null && var.metrics_endpoint_integration.url != ""
      ) : true
    )
    error_message = "`metrics_endpoint_integration` with kind `offer` needs `url`."
  }

  validation {
    condition = var.metrics_endpoint_integration == null ? true : var.metrics_endpoint_integration.kind == "offer" || alltrue([
      for app in local.opensearch_apps : app.metrics_endpoint_integration != null if !app.in_main_model
    ])
    error_message = "OpenSearch apps outside `main`'s model need their own `metrics_endpoint_integration`."
  }
}

variable "offered_endpoints" {
  description = "OpenSearch endpoints to expose as Juju offers."
  type        = list(string)
  default     = []
  nullable    = false

  validation {
    condition     = alltrue([for endpoint in var.offered_endpoints : contains(["grafana-dashboard", "metrics-endpoint", "opensearch-client"], endpoint)])
    error_message = "`offered_endpoints` may only contain `grafana-dashboard`, `metrics-endpoint` or `opensearch-client`."
  }
}

variable "opensearch_dashboards" {
  description = "Optional OpenSearch Dashboards app definition."
  type = object({
    app_name    = optional(string, "opensearch-dashboards-k8s")
    config      = optional(map(string), {})
    channel     = optional(string, "2/edge")
    base        = optional(string, "ubuntu@24.04")
    revision    = optional(number)
    units       = optional(number, 1)
    constraints = optional(string, "arch=amd64")
    resources   = optional(map(string), {})
    tls         = optional(bool, false)
    expose = optional(list(object({
      cidrs     = optional(string)
      endpoints = optional(string)
      spaces    = optional(string)
    })), [])
  })
  default = null
}

variable "s3_access_key" {
  description = "S3 access key for `s3-integrator`. Supply through `TF_VAR_s3_access_key` or `-var`, at plan and at apply."
  type        = string
  sensitive   = true
  ephemeral   = true
  default     = null
}

variable "s3_secret_key" {
  description = "S3 secret key for `s3-integrator`. Supply through `TF_VAR_s3_secret_key` or `-var`, at plan and at apply."
  type        = string
  sensitive   = true
  ephemeral   = true
  default     = null

  validation {
    condition     = (var.s3_access_key == null) == (var.s3_secret_key == null)
    error_message = "Set `s3_access_key` and `s3_secret_key` together."
  }
}

variable "s3_secret_version" {
  description = "Version of the `s3-integrator` credentials secret. Set to `1` to create, increment to rotate, `0` to remove."
  type        = number
  default     = 0

  validation {
    condition     = var.s3_secret_version == 0 || var.backups_integration != null || try(var.backups.storage_type, null) == "s3"
    error_message = "`s3_secret_version` needs an S3 integrator. Set `backups.storage_type` to `s3`."
  }

  validation {
    condition     = var.s3_secret_version == 0 || var.backups_integration == null
    error_message = "`s3_secret_version` can't be used with `backups_integration`."
  }

  validation {
    condition     = var.s3_secret_version >= 0 && floor(var.s3_secret_version) == var.s3_secret_version
    error_message = "`s3_secret_version` must be a non-negative integer."
  }
}

variable "self_signed_certificates" {
  description = "Configuration for the `self-signed-certificates` app."
  type = object({
    channel     = optional(string, "1/stable")
    revision    = optional(number)
    base        = optional(string, "ubuntu@24.04")
    units       = optional(number, 1)
    constraints = optional(string, "arch=amd64")
    config      = optional(map(string), { "ca-common-name" : "CA" })
  })
  default = {}
}
