resource "juju_offer" "offered_endpoints" {
  for_each = toset(var.offered_endpoints)

  name             = "${juju_application.opensearch.name}-${each.value}"
  application_name = juju_application.opensearch.name
  endpoints        = [each.value]
  model_uuid       = juju_application.opensearch.model_uuid
}
