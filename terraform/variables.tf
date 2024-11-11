variable "app_name" {
  description = "Application name"
  type        = string
  default     = "opensearch"
}

variable "channel" {
  description = "Charm channel"
  type        = string
  default     = null
}

variable "base" {
  description = "Charm base (old name: series)"
  type        = string
  default     = "ubuntu@22.04"
}

variable "config" {
  description = "Map of charm configuration options"
  type        = map(string)
  default     = {}
}

variable "model_name" {
  description = "Model name"
  type        = string
}

variable "revision" {
  description = "Charm revision"
  type        = number
  default     = null
}

variable "units" {
  description = "Charm units"
  type        = number
  default     = 1
}

variable "constraints" {
  description = "Map of constraints"
  type        = string
  default     = "arch=amd64"
}