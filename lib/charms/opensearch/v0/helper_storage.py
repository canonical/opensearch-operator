from typing import Optional, Literal
from charms.data_platform_libs.v0.data_interfaces import Scope
from charms.opensearch.v0.models import (
    ObjectStorageConfig, S3RelData, AzureRelData, GcsRelData, DeploymentType,
)
from charms.opensearch.v0.constants_charm import (
    S3_RELATION, AZURE_RELATION, GCS_RELATION, PeerClusterRelationName,
)


ObjectStorageType = Literal[
    "s3", "azure", "gcs", "s3-pcluster", "azure-pcluster", "gcs-pcluster", "conflict"
]

class ObjectStorageResolver:
    """Resolves active object storage type and config from relations/peer-cluster."""

    def __init__(self, charm):
        self.charm = charm

    def get_type(self) -> Optional[ObjectStorageType]:
        dep = self.charm.opensearch_peer_cm.deployment_desc()
        if not dep or dep.typ in {DeploymentType.MAIN_ORCHESTRATOR}:
            active = [r for r in [
                self.charm.model.get_relation(S3_RELATION),
                self.charm.model.get_relation(AZURE_RELATION),
                self.charm.model.get_relation(GCS_RELATION),
            ] if r]
            if len(active) > 1:
                return "conflict"
            if self.charm.model.get_relation(S3_RELATION):
                return "s3"
            if self.charm.model.get_relation(AZURE_RELATION):
                return "azure"
            if self.charm.model.get_relation(GCS_RELATION):
                return "gcs"
            if typ := self.charm.peers_data.get(Scope.UNIT, "object-storage-type"):
                return typ  # last known type
            return None

        # non-main orchestrator
        p = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        if not p or not p.credentials:
            return None
        if p.credentials.s3:
            return "s3-pcluster"
        if p.credentials.azure:
            return "azure-pcluster"
        if p.credentials.gcs:
            return "gcs-pcluster"
        if typ := self.charm.peers_data.get(Scope.UNIT, "object-storage-type"):
            return typ
        return None

    def get_config(self, forced_type: Optional[ObjectStorageType] = None) -> Optional[ObjectStorageConfig]:
        ost = forced_type or self.get_type()
        if not ost or ost == "conflict":
            return None

        if ost == "s3":
            info = self.charm.snapshot_events.s3_requirer.get_s3_connection_info()
            return ObjectStorageConfig(s3=S3RelData.from_relation(info))

        if ost == "azure":
            info = self.charm.snapshot_events.azure_requirer.get_azure_storage_connection_info()
            return ObjectStorageConfig(azure=AzureRelData.from_relation(info))

        if ost == "gcs":
            gcs_rel = self.charm.model.get_relation(GCS_RELATION)
            if not gcs_rel or not gcs_rel.app:
                return None
            return None

        p = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        if ost == "s3-pcluster":
            data = S3RelData.from_dict({
                "credentials": p.credentials.s3,
                "tls-ca-chain": p.credentials.s3_tls_ca_chain,
            })
            return ObjectStorageConfig(s3=data)
        if ost == "azure-pcluster":
            data = AzureRelData.from_dict({"credentials": p.credentials.azure})
            return ObjectStorageConfig(azure=data)
        if ost == "gcs-pcluster":
            data = GcsRelData.from_dict({"credentials": p.credentials.gcs})
            return ObjectStorageConfig(gcs=data)

        return None
