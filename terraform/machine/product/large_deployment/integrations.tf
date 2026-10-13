# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

resource "juju_integration" "this" {
  for_each   = local.integrations
  model_uuid = each.value.model_uuid

  application {
    name     = each.value.app.name
    endpoint = each.value.app.endpoint
  }

  application {
    name      = each.value.target.kind == "endpoint" ? each.value.target.name : null
    endpoint  = each.value.target.kind == "endpoint" ? each.value.target.endpoint : null
    offer_url = each.value.target.kind == "offer" ? each.value.target.url : null
  }
}

resource "terraform_data" "failover_elected" {
  count = length(local.manager_apps) > 0 ? 1 : 0

  provisioner "local-exec" {
    interpreter = ["bash"]
    command     = "${path.module}/scripts/wait_for_failover.sh"

    environment = {
      FAILOVER_APP = local.failover_app.application.name
      MAIN_APP     = local.main_app.application.name
      MAIN_MODEL   = var.main.model_uuid
      TIMEOUT      = var.failover_election_timeout
    }
  }

  depends_on = [juju_integration.this]
}

resource "juju_integration" "manager_apps" {
  for_each   = local.manager_integrations
  model_uuid = each.value.model_uuid

  application {
    name     = each.value.app.name
    endpoint = each.value.app.endpoint
  }

  application {
    name      = each.value.target.kind == "endpoint" ? each.value.target.name : null
    endpoint  = each.value.target.kind == "endpoint" ? each.value.target.endpoint : null
    offer_url = each.value.target.kind == "offer" ? each.value.target.url : null
  }

  depends_on = [terraform_data.failover_elected]
}
