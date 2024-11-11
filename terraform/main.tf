resource "juju_application" "opensearch" {
  charm {
    name     = "opensearch"
    channel  = var.channel
    revision = var.revision
  }
  config      = var.config
  model       = var.model_name
  name        = var.app_name
  units       = var.units
  constraints = var.constraints
}