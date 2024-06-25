# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import socket
import unittest
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.constants_tls import TLS_RELATION, CertType
from charms.opensearch.v0.models import (
    DeploymentDescription,
    DeploymentState,
    DeploymentType,
    PeerClusterConfig,
    StartMode,
    State,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.testing import Harness

from charm import OpenSearchOperatorCharm
from tests.helpers import create_utf8_encoded_private_key, patch_network_get


@patch_network_get("1.1.1.1")
class TestOpenSearchTLS(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"
    BASE_CHARM_CLASS = f"{BASE_LIB_PATH}.opensearch_base_charm.OpenSearchBaseCharm"

    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def setUp(self, _) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.add_network("1.1.1.1", endpoint=PeerRelationName)
        self.harness.add_network("1.1.1.1", endpoint=TLS_RELATION)
        self.harness.begin()
        self.charm = self.harness.charm
        self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.harness.add_relation(TLS_RELATION, self.charm.app.name)

        self.secret_store = self.charm.secrets

        socket.getfqdn = Mock()
        socket.getfqdn.return_value = "nebula"

    @patch(f"{BASE_LIB_PATH}.opensearch_tls.get_host_public_ip")
    @patch("socket.getfqdn")
    @patch("socket.gethostname")
    @patch("socket.gethostbyaddr")
    def test_get_sans(self, gethostbyaddr, gethostname, getfqdn, get_host_public_ip):
        """Test the SANs returned depending on the cert type."""
        self.assertDictEqual(
            self.charm.tls._get_sans(CertType.APP_ADMIN),
            {"sans_oid": ["1.2.3.4.5.5"]},
        )

        gethostbyaddr.return_value = (self.charm.unit_name, ["alias"], ["address1", "address2"])
        gethostname.return_value = "nebula"
        getfqdn.return_value = "nebula"
        get_host_public_ip.return_value = "XX.XXX.XX.XXX"

        base_ips = ["1.1.1.1", "address1", "address2"]
        base_dns_entries = [self.charm.unit_name, "nebula", "alias"]

        unit_http_sans = self.charm.tls._get_sans(CertType.UNIT_HTTP)
        self.assertDictEqual(
            dict((key, sorted(val)) for key, val in unit_http_sans.items()),
            {
                "sans_oid": ["1.2.3.4.5.5"],
                "sans_ip": sorted(base_ips + ["XX.XXX.XX.XXX"]),
                "sans_dns": sorted(base_dns_entries),
            },
        )

        unit_transport_sans = self.charm.tls._get_sans(CertType.UNIT_TRANSPORT)
        self.assertDictEqual(
            dict((key, sorted(val)) for key, val in unit_transport_sans.items()),
            {
                "sans_oid": ["1.2.3.4.5.5"],
                "sans_ip": sorted(base_ips),
                "sans_dns": sorted(base_dns_entries),
            },
        )

    def test_find_secret(self):
        """Test the secrets lookup depending on the event data."""
        event_data_cert = "cert_abcd12345"
        event_data_csr = "csr_abcd12345"

        self.assertIsNone(self.charm.tls._find_secret(event_data_cert, "cert"))
        self.assertIsNone(self.charm.tls._find_secret(event_data_csr, "csr"))

        self.secret_store.put_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, {"cert": event_data_cert}
        )
        self.secret_store.put_object(Scope.APP, CertType.APP_ADMIN.val, {"csr": event_data_csr})

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_relation_joined_admin(self, _, __, _request_certificate, deployment_desc):
        """Test on certificate relation created event."""
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=self.charm.app.name,
            state=DeploymentState(value=State.ACTIVE),
        )
        event_mock = MagicMock()

        self.harness.set_leader(is_leader=True)
        self.charm.tls._on_tls_relation_created(event_mock)
        self.assertEqual(
            _request_certificate.mock_calls,
            [
                mock.call(Scope.APP, CertType.APP_ADMIN),
                mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT),
                mock.call(Scope.UNIT, CertType.UNIT_HTTP),
            ],
        )

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_relation_joined_non_admin(self, _, __, _request_certificate, deployment_desc):
        """Test on certificate relation created event."""
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=self.charm.app.name,
            state=DeploymentState(value=State.ACTIVE),
        )
        event_mock = MagicMock()

        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_tls_relation_created(event_mock)
        self.assertEqual(
            _request_certificate.mock_calls,
            [
                mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT),
                mock.call(Scope.UNIT, CertType.UNIT_HTTP),
            ],
        )

    @patch("charm.OpenSearchOperatorCharm.on_tls_relation_broken")
    def test_on_relation_broken(self, on_tls_relation_broken):
        """Test on certificate relation broken event."""
        event_mock = MagicMock()
        self.charm.tls._on_tls_relation_broken(event_mock)

        on_tls_relation_broken.assert_called_once()

    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_set_tls_private_key(self, _, __, _request_certificate):
        """Test _on_set_tls private key event."""
        event_mock = MagicMock(params={"category": "app-admin"})

        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_set_tls_private_key(event_mock)
        _request_certificate.assert_not_called()

        self.harness.set_leader(is_leader=True)
        self.charm.tls._on_set_tls_private_key(event_mock)
        _request_certificate.assert_called_once()

        event_mock = MagicMock(params={"category": "unit-transport"})
        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_set_tls_private_key(event_mock)
        _request_certificate.assert_called()

    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charm.OpenSearchOperatorCharm.on_tls_conf_set")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.store_new_ca")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def test_on_certificate_available(self, _, on_tls_conf_set, _request_certificate, store_new_ca):
        """Test _on_certificate_available event."""
        csr = "csr_12345"
        cert = "cert_12345"
        chain = ["chain_12345"]
        ca = "ca_12345"
        secret_key = CertType.UNIT_TRANSPORT.val

        self.secret_store.put_object(Scope.UNIT, secret_key, {"csr": csr})

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )
        self.charm.tls._on_certificate_available(event_mock)

        self.assertDictEqual(
            self.secret_store.get_object(Scope.UNIT, secret_key),
            {"csr": csr, "chain": chain[0], "cert": cert, "ca-cert": ca},
        )

        on_tls_conf_set.assert_called()

    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def test_on_certificate_expiring(self, _, deployment_desc, request_certificate_creation):
        """Test _on_certificate_available event."""
        csr = "csr_12345"
        cert = "cert_12345"
        key = create_utf8_encoded_private_key()
        secret_key = CertType.UNIT_TRANSPORT.val

        self.secret_store.put_object(
            Scope.UNIT,
            secret_key,
            {"csr": csr, "cert": cert, "key": key},
        )

        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=self.charm.app.name,
            state=DeploymentState(value=State.ACTIVE),
        )

        event_mock = MagicMock(certificate=cert)
        self.charm.tls._on_certificate_expiring(event_mock)

        request_certificate_creation.assert_called_once()

    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_renewal"
    )
    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def test_on_certificate_invalidated(self, _, deployment_desc, request_certificate_renewal):
        """Test _on_certificate_invalidated event."""
        csr = "csr_12345"
        cert = "cert_12345"
        key = create_utf8_encoded_private_key()
        secret_key = CertType.UNIT_TRANSPORT.val

        self.secret_store.put_object(
            Scope.UNIT,
            secret_key,
            {"csr": csr, "cert": cert, "key": key},
        )

        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=self.charm.app.name,
            state=DeploymentState(value=State.ACTIVE),
        )

        event_mock = MagicMock(certificate=cert)
        self.charm.tls._on_certificate_invalidated(event_mock)

        request_certificate_renewal.assert_called_once()
