module "opensearch" {
  source     = "../"
  app_name   = var.app_name
  model = var.model_name
  units      = var.simple_opensearch_units
  config = {
    profile = "testing"
  }

  channel = "2/edge"

  depends_on = [juju_application.self-signed-certificates]
}

resource "juju_integration" "simple_deployment_tls-operator_opensearch-integration" {
  model = var.model_name

  application {
    name = juju_application.self-signed-certificates.name
  }
  application {
    name = var.app_name
  }
  depends_on = [
    juju_application.self-signed-certificates,
    module.opensearch
  ]

}

resource "null_resource" "simple_deployment_juju_wait_deployment" {
  provisioner "local-exec" {
    command = <<-EOT
    juju-wait -v --model ${var.model_name}
    EOT
  }

  depends_on = [juju_integration.simple_deployment_tls-operator_opensearch-integration]
}
