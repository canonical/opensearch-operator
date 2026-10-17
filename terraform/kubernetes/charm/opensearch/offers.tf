# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

resource "juju_offer" "offered_endpoints" {
  for_each = toset(var.offered_endpoints)

  name             = "${juju_application.opensearch_k8s.name}-${each.value}"
  application_name = juju_application.opensearch_k8s.name
  endpoints        = [each.value]
  model_uuid       = juju_application.opensearch_k8s.model_uuid
}
