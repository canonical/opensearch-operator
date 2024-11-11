resource "null_resource" "preamble" {
  provisioner "local-exec" {
    command = <<-EOT
    sudo snap install juju-wait --classic || true
    sudo sysctl -w vm.max_map_count=262144 vm.swappiness=0 net.ipv4.tcp_retries2=5
    EOT
  }

}

resource "juju_application" "self-signed-certificates" {
  charm {
    name    = "self-signed-certificates"
    channel = "latest/stable"
  }
  model      = var.model_name
  depends_on = [null_resource.preamble]
}