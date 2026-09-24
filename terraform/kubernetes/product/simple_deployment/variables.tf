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
  })

  default = null

  validation {
    condition     = var.backups-integrator == null ? true : contains(["s3", "azure-storage", "gcs"], var.backups-integrator.storage_type)
    error_message = "storage_type must be 's3', 'azure-storage' or 'gcs'."
  }
}

variable "certificates_integration" {
  description = "External TLS endpoint or offer."
  type = object({
    kind       = string
    name       = optional(string)
    endpoint   = optional(string)
    url        = optional(string)
    controller = optional(string)
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

variable "data-integrator" {
  description = "Configuration for the optional data-integrator"
  type = object({
    model_uuid  = optional(string)
    config      = optional(map(string), { "index-name" : "test", "extra-user-roles" : "admin" })
    channel     = optional(string, "latest/edge")
    base        = optional(string, "ubuntu@22.04")
    revision    = optional(number)
    constraints = optional(string, "arch=amd64")
  })
  default = null

  validation {
    condition = var.data-integrator == null ? true : (
      lookup(var.data-integrator.config, "index-name", "") != ""
      && contains(["default", "admin"], lookup(var.data-integrator.config, "extra-user-roles", "admin"))
    )
    error_message = "data-integrator config must contain a non-empty 'index-name' and 'extra-user-roles' must be either 'default' or 'admin'."
  }
}

variable "grafana_dashboard_integration" {
  description = "Optional COS Grafana dashboard endpoint or offer."
  type = object({
    kind       = string
    name       = optional(string)
    endpoint   = optional(string)
    url        = optional(string)
    controller = optional(string)
  })
  default = null

  validation {
    condition     = var.grafana_dashboard_integration == null ? true : contains(["endpoint", "offer"], var.grafana_dashboard_integration.kind)
    error_message = "grafana_dashboard_integration.kind must be either 'endpoint' or 'offer'."
  }

  validation {
    condition = (
      var.grafana_dashboard_integration == null ? true :
      var.grafana_dashboard_integration.kind == "endpoint" ? (
        var.grafana_dashboard_integration.name != null && var.grafana_dashboard_integration.name != "" &&
        var.grafana_dashboard_integration.endpoint != null && var.grafana_dashboard_integration.endpoint != ""
      ) : true
    )
    error_message = "Both 'name' and 'endpoint' attributes must be provided for an in-model integration."
  }

  validation {
    condition = (
      var.grafana_dashboard_integration == null ? true :
      var.grafana_dashboard_integration.kind == "offer" ? (
        var.grafana_dashboard_integration.url != null && var.grafana_dashboard_integration.url != ""
      ) : true
    )
    error_message = "The 'url' attribute must be provided for a cross-model integration."
  }
}

variable "ingress_integration" {
  description = "External ingress endpoint or offer for OpenSearch Dashboards, used instead of the bundled traefik-k8s."
  type = object({
    kind       = string
    name       = optional(string)
    endpoint   = optional(string)
    url        = optional(string)
    controller = optional(string)
  })
  default = null

  validation {
    condition     = var.ingress_integration == null ? true : contains(["endpoint", "offer"], var.ingress_integration.kind)
    error_message = "ingress_integration.kind must be either 'endpoint' or 'offer'."
  }

  validation {
    condition = (
      var.ingress_integration == null ? true :
      var.ingress_integration.kind == "endpoint" ? (
        var.ingress_integration.name != null && var.ingress_integration.name != "" &&
        var.ingress_integration.endpoint != null && var.ingress_integration.endpoint != ""
      ) : true
    )
    error_message = "Both 'name' and 'endpoint' attributes must be provided for an in-model integration."
  }

  validation {
    condition = (
      var.ingress_integration == null ? true :
      var.ingress_integration.kind == "offer" ? (
        var.ingress_integration.url != null && var.ingress_integration.url != ""
      ) : true
    )
    error_message = "The 'url' attribute must be provided for a cross-model integration."
  }
}

variable "logging_integration" {
  description = "Optional COS logging endpoint or offer."
  type = object({
    kind       = string
    name       = optional(string)
    endpoint   = optional(string)
    url        = optional(string)
    controller = optional(string)
  })
  default = null

  validation {
    condition     = var.logging_integration == null ? true : contains(["endpoint", "offer"], var.logging_integration.kind)
    error_message = "logging_integration.kind must be either 'endpoint' or 'offer'."
  }

  validation {
    condition = (
      var.logging_integration == null ? true :
      var.logging_integration.kind == "endpoint" ? (
        var.logging_integration.name != null && var.logging_integration.name != "" &&
        var.logging_integration.endpoint != null && var.logging_integration.endpoint != ""
      ) : true
    )
    error_message = "Both 'name' and 'endpoint' attributes must be provided for an in-model integration."
  }

  validation {
    condition = (
      var.logging_integration == null ? true :
      var.logging_integration.kind == "offer" ? (
        var.logging_integration.url != null && var.logging_integration.url != ""
      ) : true
    )
    error_message = "The 'url' attribute must be provided for a cross-model integration."
  }
}

variable "metrics_endpoint_integration" {
  description = "Optional COS metrics endpoint or offer."
  type = object({
    kind       = string
    name       = optional(string)
    endpoint   = optional(string)
    url        = optional(string)
    controller = optional(string)
  })
  default = null

  validation {
    condition     = var.metrics_endpoint_integration == null ? true : contains(["endpoint", "offer"], var.metrics_endpoint_integration.kind)
    error_message = "metrics_endpoint_integration.kind must be either 'endpoint' or 'offer'."
  }

  validation {
    condition = (
      var.metrics_endpoint_integration == null ? true :
      var.metrics_endpoint_integration.kind == "endpoint" ? (
        var.metrics_endpoint_integration.name != null && var.metrics_endpoint_integration.name != "" &&
        var.metrics_endpoint_integration.endpoint != null && var.metrics_endpoint_integration.endpoint != ""
      ) : true
    )
    error_message = "Both 'name' and 'endpoint' attributes must be provided for an in-model integration."
  }

  validation {
    condition = (
      var.metrics_endpoint_integration == null ? true :
      var.metrics_endpoint_integration.kind == "offer" ? (
        var.metrics_endpoint_integration.url != null && var.metrics_endpoint_integration.url != ""
      ) : true
    )
    error_message = "The 'url' attribute must be provided for a cross-model integration."
  }
}

variable "opensearch" {
  description = "OpenSearch app definition"
  type = object({
    app_name           = optional(string, "opensearch-k8s")
    model_uuid         = string
    config             = optional(map(string), { "cluster_name" : "opensearch" })
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
}

variable "opensearch-dashboards" {
  description = "Optional OpenSearch Dashboards app definition"
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

variable "self-signed-certificates" {
  description = "Configuration for the self-signed-certificates app"
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

variable "traefik-k8s" {
  description = "Configuration for the traefik-k8s app, deployed with OpenSearch Dashboards unless ingress_integration is set"
  type = object({
    channel     = optional(string, "latest/stable")
    revision    = optional(number)
    base        = optional(string)
    units       = optional(number, 1)
    constraints = optional(string, "arch=amd64")
    config      = optional(map(string), {})
  })
  default = {}
}
