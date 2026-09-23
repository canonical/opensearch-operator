variable "app_name" {
  description = "Application name."
  type        = string
  default     = "opensearch"
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
  description = "Machine constraints."
  type        = string
  default     = null
}

variable "endpoint_bindings" {
  description = "Map of endpoint bindings."
  type        = set(object({ space = string, endpoint = optional(string) }))
  default     = []
  nullable    = false
}

variable "expose" {
  description = "Expose the application for external access."
  type        = list(object({ cidrs = optional(string), endpoints = optional(string), spaces = optional(string) }))
  default     = []
  nullable    = false
}

variable "machines" {
  description = "List of machines for placement."
  type        = set(string)
  default     = []
  nullable    = false
}

variable "model_uuid" {
  description = "Model UUID"
  type        = string
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
  description = "Charm units"
  type        = number
  default     = 1
}
