resource "juju_offer" "main_orchestrator" {
  name             = "${module.opensearch_main.application.name}-peer-cluster-orchestrator"
  model_uuid       = local.main_model_uuid
  application_name = module.opensearch_main.provides.peer_cluster_orchestrator.name
  endpoints        = [module.opensearch_main.provides.peer_cluster_orchestrator.endpoint]
}

resource "juju_offer" "failover_orchestrator" {
  count = local.failover_enabled ? 1 : 0

  name             = "${module.opensearch_failover[0].application.name}-peer-cluster-orchestrator"
  model_uuid       = local.failover_model_uuid
  application_name = module.opensearch_failover[0].provides.peer_cluster_orchestrator.name
  endpoints        = [module.opensearch_failover[0].provides.peer_cluster_orchestrator.endpoint]
}

resource "juju_offer" "certificates" {
  count = local.self_signed_enabled ? 1 : 0

  name             = "${juju_application.self-signed-certificates[0].name}-certificates"
  model_uuid       = local.main_model_uuid
  application_name = juju_application.self-signed-certificates[0].name
  endpoints        = ["certificates"]
}

resource "juju_offer" "opensearch_client" {
  count = local.data_integrator_enabled ? 1 : 0

  name             = "${module.opensearch_main.application.name}-opensearch-client"
  model_uuid       = local.main_model_uuid
  application_name = module.opensearch_main.provides.opensearch_client.name
  endpoints        = [module.opensearch_main.provides.opensearch_client.endpoint]
}

resource "juju_offer" "backups_credentials" {
  count = local.backups_enabled ? 1 : 0

  name             = "${juju_application.backups-integrator[0].name}-${local.backups_settings[var.backups-integrator.storage_type].endpoint}"
  model_uuid       = local.backups_model_uuid
  application_name = juju_application.backups-integrator[0].name
  endpoints        = [local.backups_settings[var.backups-integrator.storage_type].endpoint]
}
