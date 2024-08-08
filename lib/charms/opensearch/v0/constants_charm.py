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
PClusterWrongRelation = "Cluster name don't match with related cluster. Remove relation."
PClusterWrongRolesProvided = "Cannot start cluster with current set of roles."
PClusterWrongNodesCountForQuorum = (
    "Even number of members in quorum if current unit started. Add or remove 1 unit."
)
PluginConfigError = "Unexpected error during plugin configuration, check the logs"
BackupSetupFailed = "Backup setup failed, check logs for details"
S3RelMissing = "Backup failover cluster missing S3 relation."
S3RelShouldNotExist = "This unit should not be related to S3"
S3RelDataIncomplete = "S3 relation data missing or incomplete."
S3RelUneligible = "Only orchestrator clusters should relate to S3."

# Wait status
RequestUnitServiceOps = "Requesting lock on operation: {}"
BackupDeferRelBrokenAsInProgress = "Backup service cannot be stopped: backup in progress."


# Maintenance statuses
InstallProgress = "Installing OpenSearch..."
SecurityIndexInitProgress = "Initializing the security index..."
AdminUserInitProgress = "Configuring admin user..."
TLSNewCertsRequested = "Requesting new TLS certificates..."
HorizontalScaleUpSuggest = "Horizontal scale up advised: {} shards unassigned."
WaitingForOtherUnitServiceOps = "Waiting for other units to complete the ops on their service."
NewIndexRequested = "new index {index} requested"
RestoreInProgress = "Restore in progress..."
PluginConfigCheck = "Plugin configuration check."
BackupSetupStart = "Backup setup started."
BackupConfigureStart = "Configuring backup service..."
BackupInDisabling = "Disabling backup service..."

# Relation Interfaces
ClientRelationName = "opensearch-client"
PeerRelationName = "opensearch-peers"
PeerClusterOrchestratorRelationName = "peer-cluster-orchestrator"
PeerClusterRelationName = "peer-cluster"
COSUser = "monitor"
COSRelationName = "cos-agent"
COSRole = "readall_and_monitor"
COSPort = "9200"


# Opensearch Users
OpenSearchSystemUsers = {"admin", "kibanaserver"}
OpenSearchUsers = OpenSearchSystemUsers | {"monitor"}
OpenSearchRoles = set()
AdminUser = "admin"
KibanaserverUser = "kibanaserver"
KibanaserverRole = "kibana_server"

# Opensearch Snap revision
OPENSEARCH_SNAP_REVISION = 54  # Keep in sync with `workload_version` file

# User-face Backup ID format
OPENSEARCH_BACKUP_ID_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
