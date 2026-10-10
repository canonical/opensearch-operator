resource "juju_offer" "backups_credentials" {
  count = local.backups_enabled ? 1 : 0

  model_uuid       = local.backups_model_uuid
  application_name = juju_application.backups-integrator[0].name
  endpoints        = [local.backups_settings[var.backups-integrator.storage_type].endpoint]
}
