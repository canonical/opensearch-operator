variable "model_name" {
  description = "Model name"
  type        = string
}

variable "app_name" {
  description = "OpenSearch app name"
  type        = string
  default     = "opensearch"
}

variable "simple_opensearch_units" {
  description = "Node count"
  type        = number
  default     = 1
}
