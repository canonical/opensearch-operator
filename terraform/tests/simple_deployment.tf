module "opensearch" {
  source     = "../"
  app_name   = var.app_name
  model_name = var.model_name
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

# # We know the machine ids because we explicitly wait for the self-signed-certificates unit
# # to start before deploying opensearch itself.
# data "juju_machine" "simple_deployment_opensearch_machine" {
#   for_each = var.simple_opensearch_units

#   model      = juju_model.development.name
#   machine_id = each.value + juju_application.self-signed-certificates.units
#   depends_on = [null_resource.simple_deployment_juju_wait_deployment]
# }

# data "external" "opensearch_addresses" {
#   count = var.simple_opensearch_units

#   program = ["juju", "exec", "-m", "${var.model_name}", "--unit", "${var.app_name}/${count.index}", "echo", "'{\"addr\": \"$IP\"}'"]
#   # program = ["IP=$(juju ssh -m ${var.model_name} ${var.app_name}/${count.index} -- ip r get 8.8.8.8 | awk '{print $7}' | head -1); echo '{\"addr\": \"$IP\"}'"]
#   # program = <<-EOT
#   # IP=$(juju ssh -m ${var.model_name} ${var.app_name}/${each.value} -- ip r get 8.8.8.8 | awk '{print $7}' | head -1)
#   # echo "{\"addr\": \"$IP\"}"
#   # EOT
#   depends_on = [null_resource.simple_deployment_juju_wait_deployment]
# }



# locals {
#     opensearch_address = jsondecode(file("/tmp/juju-status.json"))["applications"]["opensearch"]["units"]
# }



# resource null_resource "opensearch_addresses" {
#   count = var.simple_opensearch_units

#   triggers = {
#     opensearch_status = jsonencode(local.opensearch_address)
#   }

#   provisioner "local-exec" {
#     command = <<-EOT
#     echo ${local.opensearch_address["${var.app_name}/${count.index}"]["public-address"]} > /tmp/opensearch-address-${count.index}.txt
#     EOT
#   }

#   depends_on = [null_resource.simple_deployment_juju_wait_deployment]
# }


# data "http" "curl_opensearch" {
#   count = var.simple_opensearch_units

#   url = "http://${local.opensearch_address[var.app_name/count.index]["public-address"]}:9200"

#   depends_on = [data.external.opensearch_addresses]
# }
