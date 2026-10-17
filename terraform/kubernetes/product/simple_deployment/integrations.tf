# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

#--------------------------------------------------------
# 2. INTEGRATIONS
#--------------------------------------------------------

resource "juju_integration" "this" {
  for_each   = local.integrations
  model_uuid = var.opensearch.model_uuid

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
