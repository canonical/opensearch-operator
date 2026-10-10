# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

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
    machines               = optional(list(string), [])
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

  validation {
    condition     = var.backups == null ? true : length(var.backups.machines) <= 1
    error_message = "`backups.machines` takes at most one machine."
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
}

variable "cos_agent_integration" {
  description = "COS agent endpoint."
  type = object({
    name     = string
    endpoint = string
  })
  default = null
}

variable "data_integrator" {
  description = "Configuration for the optional `data-integrator`."
  type = object({
    config      = optional(map(string), { "index-name" : "test", "extra-user-roles" : "admin" })
    channel     = optional(string, "latest/stable")
    base        = optional(string, "ubuntu@22.04")
    revision    = optional(number)
    constraints = optional(string, "arch=amd64")
    machines    = optional(list(string), [])
  })
  default = null

  validation {
    condition = var.data_integrator == null ? true : (
      lookup(var.data_integrator.config, "index-name", "") != ""
      && contains(["default", "admin"], lookup(var.data_integrator.config, "extra-user-roles", "admin"))
    )
    error_message = "`data_integrator.config` needs a non-empty `index-name`, and `extra-user-roles` must be `default` or `admin`."
  }

  validation {
    condition     = var.data_integrator == null ? true : length(var.data_integrator.machines) <= 1
    error_message = "`data_integrator.machines` takes at most one machine."
  }
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

variable "offered_endpoints" {
  description = "OpenSearch endpoints to expose as Juju offers."
  type        = list(string)
  default     = []
  nullable    = false

  validation {
    condition     = alltrue([for endpoint in var.offered_endpoints : endpoint == "opensearch-client"])
    error_message = "`offered_endpoints` may only contain `opensearch-client`."
  }
}

variable "opensearch" {
  description = "OpenSearch app definition."
  type = object({
    app_name           = optional(string, "opensearch")
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
}

variable "opensearch_dashboards" {
  description = "Optional OpenSearch Dashboards app definition."
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
    machines    = optional(list(string), [])
    config      = optional(map(string), { "ca-common-name" : "CA" })
  })
  default = {}

  validation {
    condition     = length(var.self_signed_certificates.machines) <= 1
    error_message = "`self_signed_certificates.machines` takes at most one machine."
  }
}
