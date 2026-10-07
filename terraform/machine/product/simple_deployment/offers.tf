resource "juju_offer" "opensearch_client" {
  count = local.data_integrator_enabled ? 1 : 0

  model_uuid       = var.opensearch.model_uuid
  application_name = module.opensearch.provides.opensearch_client.name
  endpoints        = [module.opensearch.provides.opensearch_client.endpoint]
}

resource "juju_offer" "backups_credentials" {
  count = local.backups_enabled ? 1 : 0

  model_uuid       = local.backups_model_uuid
  application_name = juju_application.backups-integrator[0].name
  endpoints        = [local.backups_settings[var.backups-integrator.storage_type].endpoint]
}
