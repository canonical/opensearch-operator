# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this file we declare the constants and enums used by the charm."""

# The unique Charmhub library identifier, never change it
LIBID = "a8e3e482b22f4552ad6211ea77b46f7b"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


# Blocked statuses
WaitingToStart = "Waiting for OpenSearch to start..."
InstallError = "Could not install OpenSearch."
CertsExpirationError = "The certificates: {} need to be refreshed."
WaitingForBusyShards = "Some shards are still initializing / relocating."
WaitingForSpecificBusyShards = "The shards: {} need to complete building."
ExclusionFailed = "The {} exclusion(s) of this node failed."
AllocationExclusionFailed = "The exclusion of this node from the allocations failed."
VotingExclusionFailed = "The exclusion of this node from the voting list failed."
ServiceStartError = "An error occurred during the start of the OpenSearch service."
ServiceStopped = "The OpenSearch service stopped."
ServiceStopFailed = "An error occurred while attempting to stop the OpenSearch service."
ServiceIsStopping = "The OpenSearch service is stopping."
AdminUserNotConfigured = "Waiting for the admin user to be fully configured..."
TLSNotFullyConfigured = "Waiting for TLS to be fully configured..."
TLSRelationMissing = "Missing TLS relation with this cluster."
TLSRelationBrokenError = (
    "Relation broken with the TLS Operator while TLS not fully configured. Stopping OpenSearch."
)
NoNodeUpInCluster = "No node is up in this cluster."
TooManyNodesRemoved = (
    "Too many nodes being removed at the same time, please scale your application up."
)
ClusterHealthRed = "1 or more 'primary' shards are not assigned, please scale your application up."
ClusterHealthUnknown = "No unit online, cannot determine if it's safe to scale-down."
ClusterHealthYellow = (
    "1 or more 'replica' shards are not assigned, please scale your application up."
)
ClusterHealthRedUpgrade = (
    "1 or more 'primary' shards are not assigned in the cluster. Fix unhealthy units"
)
IndexCreationFailed = "failed to create {index} index - deferring index-requested event..."
UserCreationFailed = "failed to create users for {rel_name} relation {id}"
PluginConfigChangeError = "Failed to apply config changes on the plugin."

CmVoRolesProvidedInvalid = (
    "cluster_manager and voting_only roles cannot be both set on the same nodes."
)
CMRoleRemovalForbidden = "Removal of cluster_manager role from deployment not allowed."
DataRoleRemovalForbidden = (
    "Removal of data role from current deployment not allowed - the data cannot be reallocated."
)
PClusterNoRelation = "Cannot start. Waiting for peer cluster relation..."
PClusterOrchestratorsRemoved = (
    "Main-cluster-orchestrator removed, and no failover cluster related."
)
PClusterWrongRelation = "Cluster name don't match with related cluster. Remove relation."
PClusterWrongRolesProvided = "Cannot start cluster with current set of roles."
PClusterNoDataNode = "Cannot run cluster with current roles. Waiting for data node..."
PClusterWrongNodesCountForQuorum = (
    "Less than 3 cluster-manager-eligible units in this cluster. Add more units."
)
PluginConfigError = "Unexpected error during plugin configuration, check the logs"
PClusterMissingStorageRelations = "Found credentials with missing storage relations. Add relation for {} and any client applications."
BackupSetupFailed = "Backup setup failed, check logs for details"
BackupRelShouldNotExist = "This application should not be related to backup relation"
BackupRelDataIncomplete = "Backup relation data missing or incomplete."
BackupCredentialIncorrect = "Backup configuration error: bad credentials, permissions, invalid CA, or unsupported configuration."
BackupCredentialCleanupFailed = "Failed to remove keystore credentials or snapshot repository. Please check the logs for more details."
BackupRelConflict = "Too many object storage relations. Only one is supported."
BackupMisconfiguration = "opensearch {} repository setup failed. Check the {} config."
BackupRelUneligible = "Only orchestrator clusters should relate to backup relation."
SecretAccessError = "Failed to access secret, please check permissions."
JWTAuthConfigInvalid = (
    "Configuration for JWT authentication is invalid. Check and correct parameters."
)
JWTRelationInvalid = "JWT relation must be created with Main-cluster-orchestrator"
OAuthRelationInvalid = "OAuth relation must be created with Main-cluster-orchestrator"
SecurityIndexUpdateError = "Failed to update security configuration, check logs for details."

# Wait status
RequestUnitServiceOps = "Requesting lock on operation: {}"
BackupDeferRelBrokenAsInProgress = "Backup service cannot be stopped: backup in progress."
PClusterWaitingForFailoverPromotion = (
    "Main-cluster-orchestrator removed, waiting for failover promotion."
)
PClusterMainIsRequirer = "Main orchestrator cannot be a requirer"
InvalidProfileConfigOption = (
    "Invalid profile configuration option. Only `production` and `testing` values are allowed."
)

# Maintenance statuses
InstallProgress = "Installing OpenSearch..."
SecurityIndexInitProgress = "Initializing the security index..."
AdminUserInitProgress = "Configuring admin user..."
TLSNewCertsRequested = "Requesting new TLS certificates..."
TLSCaRotation = "Applying new CA certificate..."
HorizontalScaleUpSuggest = "Horizontal scale up advised: {} shards unassigned."
WaitingForOtherUnitServiceOps = "Waiting for other units to complete the ops on their service."
NewIndexRequested = "new index {index} requested"
RestoreInProgress = "Restore in progress..."
BackupInProgress = "Backup in progress..."
BackupSetupStart = "Backup setup started."
BackupConfigureStart = "Configuring backup service..."
BackupInDisabling = "Disabling backup service..."
PluginConfigCheck = "Plugin configuration check."

# Relation Interfaces
ClientRelationName = "opensearch-client"
PeerRelationName = "opensearch-peers"
NodeLockRelationName = "node-lock-fallback"
PeerClusterOrchestratorRelationName = "peer-cluster-orchestrator"
PeerClusterRelationName = "peer-cluster"
COSUser = "monitor"
COSRelationName = "cos-agent"
COSRole = "readall_and_monitor"
COSPort = "9200"
GeneratedRoles = ["data", "ingest", "ml", "cluster_manager"]


# Opensearch Users
OpenSearchSystemUsers = {"admin", "kibanaserver"}
OpenSearchUsers = OpenSearchSystemUsers | {"monitor"}
OpenSearchRoles = set()
AdminUser = "admin"
KibanaserverUser = "kibanaserver"
KibanaserverRole = "kibana_server"
ClientUsersDict = "client_relation_users"


# Opensearch Snap revision
OPENSEARCH_SNAP_REVISION = 98  # Keep in sync with `workload_version` file

# User-face Backup ID format
OPENSEARCH_BACKUP_ID_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

S3_RELATION = "s3-credentials"
AZURE_RELATION = "azure-credentials"
GCS_RELATION = "gcs-credentials"

OAUTH_RELATION = "oauth"

PERFORMANCE_PROFILE = "profile"

JWT_CONFIG_RELATION = "jwt-configuration"
