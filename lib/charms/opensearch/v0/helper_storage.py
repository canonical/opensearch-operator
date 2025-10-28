# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""OpenSearch StorageResolver."""
import logging
from typing import Literal, Optional

from charms.data_platform_libs.v0.data_interfaces import Scope
from charms.opensearch.v0.constants_charm import (
    AZURE_RELATION,
    GCS_RELATION,
    S3_RELATION,
)
from charms.opensearch.v0.models import (
    AzureRelData,
    DeploymentType,
    GcsRelData,
    ObjectStorageConfig,
    S3RelData,
)
from pydantic import ValidationError

ObjectStorageType = Literal[
    "s3", "azure", "gcs", "s3-pcluster", "azure-pcluster", "gcs-pcluster", "conflict"
]

logger = logging.getLogger(__name__)


class ObjectStorageResolver:
    """Resolves active object storage type and config from relations/peer-cluster."""

    def __init__(self, charm):
        """Initialize the object storage resolver object."""
        self.charm = charm

    def get_storage_type(self) -> Optional[ObjectStorageType]:  # noqa: C901
        """Get the active object storage type from relations/peer-cluster."""
        dep = self.charm.opensearch_peer_cm.deployment_desc()
        dep_typ = getattr(dep, "typ", DeploymentType.MAIN_ORCHESTRATOR)
        if not dep or dep_typ in {DeploymentType.MAIN_ORCHESTRATOR}:
            active = [
                r
                for r in [
                    self.charm.model.get_relation(S3_RELATION),
                    self.charm.model.get_relation(AZURE_RELATION),
                    self.charm.model.get_relation(GCS_RELATION),
                ]
                if r
            ]
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
            return

        # non-main orchestrator
        peer_data = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        if not peer_data or not peer_data.credentials:
            return
        if peer_data.credentials.s3:
            return "s3-pcluster"
        if peer_data.credentials.azure:
            return "azure-pcluster"
        if peer_data.credentials.gcs:
            return "gcs-pcluster"
        if typ := self.charm.peers_data.get(Scope.UNIT, "object-storage-type"):
            return typ
        return

    def get_storage_config(  # noqa: C901
        self, forced_type: Optional[ObjectStorageType] = None
    ) -> Optional[ObjectStorageConfig]:
        """Get the active object storage config from relations/peer-cluster."""
        object_storage_type = forced_type or self.get_storage_type()
        if not object_storage_type or object_storage_type == "conflict":
            return

        if object_storage_type == "s3":
            info = self.charm.snapshot_events.s3_requirer.get_s3_connection_info()

            try:
                s3 = S3RelData.from_relation(info) if info else None
            except ValidationError as e:
                logger.warning("validation error while building s3 payload: %s", e)
                s3 = None
            return ObjectStorageConfig(s3=s3) if s3 else None

        if object_storage_type == "azure":
            info = self.charm.snapshot_events.azure_requirer.get_azure_storage_connection_info()
            try:
                azure = AzureRelData.from_relation(info) if info else None
            except ValidationError as e:
                logger.warning("validation error while building azure payload: %s", e)
                azure = None
            return ObjectStorageConfig(azure=azure) if azure else None

        if object_storage_type == "gcs":
            gcs_rel = self.charm.model.get_relation(GCS_RELATION)
            if not gcs_rel or not gcs_rel.app:
                return
            return

        peer_data = self.charm.opensearch_peer_cm.rel_data(peek_secrets=True)
        if object_storage_type == "s3-pcluster":
            try:
                data = S3RelData.from_dict(
                    {
                        "credentials": peer_data.credentials.s3,
                        "tls-ca-chain": peer_data.credentials.s3_tls_ca_chain,
                    }
                )

            except ValidationError as e:
                logger.warning("validation error while building s3-pcluster payload: %s", e)
                data = None
            return ObjectStorageConfig(s3=data) if data else None

        if object_storage_type == "azure-pcluster":
            try:
                data = AzureRelData.from_dict({"credentials": peer_data.credentials.azure})
            except ValidationError as e:
                logger.warning("validation error while building azure-pcluster payload: %s", e)
                data = None
            return ObjectStorageConfig(azure=data) if data else None

        if object_storage_type == "gcs-pcluster":
            try:
                data = GcsRelData.from_dict({"credentials": peer_data.credentials.gcs})
            except ValidationError as e:
                logger.warning("validation error while building gcs-pcluster payload: %s", e)
                data = None
            return ObjectStorageConfig(gcs=data) if data else None

        return
