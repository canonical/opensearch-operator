# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import itertools
import re
import socket
import unittest
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import responses
from charms.opensearch.v0.constants_charm import (
    PeerRelationName,
    TLSCaRotation,
    TLSNotFullyConfigured,
)
from charms.opensearch.v0.constants_tls import TLS_RELATION, CertType
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    DeploymentType,
    Directive,
    PeerClusterConfig,
    StartMode,
    State,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from ops.model import ActiveStatus, MaintenanceStatus
from ops.testing import Harness
from parameterized import parameterized

from charm import OpenSearchOperatorCharm
from tests.helpers import create_utf8_encoded_private_key, patch_network_get
from tests.unit.helpers import (
    mock_response_health_green,
    mock_response_lock_not_requested,
    mock_response_nodes,
    mock_response_put_http_cert,
    mock_response_put_transport_cert,
    mock_response_root,
)


def single_space(input: str) -> str:
    """Replace multiple spaces with one."""
    return " ".join(input.split())


@patch_network_get("1.1.1.1")
class TestOpenSearchTLS(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"
    BASE_CHARM_CLASS = f"{BASE_LIB_PATH}.opensearch_base_charm.OpenSearchBaseCharm"
    PEER_CLUSTERS_MANAGER = (
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager"
    )

    deployment_descriptions = {
        "ok": DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid="model-uuid", name="opensearch"),
            state=DeploymentState(value=State.ACTIVE),
        ),
        "ko": DeploymentDescription(
            config=PeerClusterConfig(cluster_name="logs", init_hold=True, roles=["ml"]),
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[Directive.WAIT_FOR_PEER_CLUSTER_RELATION],
            typ=DeploymentType.OTHER,
            app=App(model_uuid="model-uuid", name="opensearch"),
            state=DeploymentState(value=State.BLOCKED_CANNOT_START_WITH_ROLES, message="error"),
        ),
    }

    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def setUp(self, _) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.rel_id = self.harness.add_network("1.1.1.1", endpoint=PeerRelationName)
        self.harness.add_network("1.1.1.1", endpoint=TLS_RELATION)
        self.harness.begin()
        self.charm = self.harness.charm
        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.harness.add_relation_unit(self.rel_id, f"{self.charm.app.name}/0")
        self.harness.add_relation(TLS_RELATION, self.charm.app.name)

        self.secret_store = self.charm.secrets

        socket.getfqdn = Mock()
        socket.getfqdn.return_value = "nebula"

        self.charm.opensearch.config = YamlConfigSetter(base_path="tests/unit/resources/config")

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.get_host_public_ip")
    @patch("socket.getfqdn")
    @patch("socket.gethostname")
    @patch("socket.gethostbyaddr")
    def test_get_sans(
        self, gethostbyaddr, gethostname, getfqdn, get_host_public_ip, deployment_desc
    ):
        """Test the SANs returned depending on the cert type."""
        deployment_desc.return_value = self.deployment_descriptions["ok"]

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
    def test_on_relation_created_admin(self, _, __, _request_certificate, deployment_desc):
        """Test on certificate relation created event."""
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
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
    def test_on_relation_created_only_main_orchestrator_requests_application_cert(
        self, _, __, _request_certificate, deployment_desc
    ):
        """Test on certificate relation created event."""
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.OTHER,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        # Truststore password is required
        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {"truststore-password": "abc"},
        )
        event_mock = MagicMock()

        self.harness.set_leader(is_leader=True)
        self.charm.tls._on_tls_relation_created(event_mock)

        self.assertEqual(
            _request_certificate.mock_calls,
            [
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
    def test_on_relation_created_non_admin(self, _, __, _request_certificate, deployment_desc):
        """Test on certificate relation created event."""
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        event_mock = MagicMock()
        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {"truststore-password": "abc"},
        )

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

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_set_tls_private_key(self, _, __, _request_certificate, deployment_desc):
        """Test _on_set_tls private key event."""
        event_mock = MagicMock(params={"category": "app-admin"})

        self.harness.set_leader(is_leader=False)
        deployment_desc.return_value = self.deployment_descriptions["ko"]
        self.charm.tls._on_set_tls_private_key(event_mock)
        _request_certificate.assert_not_called()

        self.harness.set_leader(is_leader=True)
        deployment_desc.return_value = self.deployment_descriptions["ok"]
        self.charm.tls._on_set_tls_private_key(event_mock)
        _request_certificate.assert_called_once()

        event_mock = MagicMock(params={"category": "unit-transport"})
        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_set_tls_private_key(event_mock)
        _request_certificate.assert_called()

    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._request_certificate")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charm.OpenSearchOperatorCharm.on_tls_conf_set")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.store_new_ca")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def test_on_certificate_available(
        self,
        _,
        on_tls_conf_set,
        _request_certificate,
        store_new_ca,
        _create_keystore_pwd_if_not_exists,
    ):
        """Test _on_certificate_available event."""
        csr = "csr_12345"
        cert = "cert_12345"
        chain = ["chain_12345"]
        ca = "ca_12345"
        keystore_password = "keystore_12345"
        secret_key = CertType.UNIT_TRANSPORT.val

        self.secret_store.put_object(
            Scope.UNIT,
            secret_key,
            {"csr": csr, "keystore-password": keystore_password},
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )
        self.charm.tls._on_certificate_available(event_mock)

        self.assertDictEqual(
            self.secret_store.get_object(Scope.UNIT, secret_key),
            {
                "csr": csr,
                "chain": chain[0],
                "cert": cert,
                "ca-cert": ca,
                "keystore-password": keystore_password,
            },
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
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
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
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )

        event_mock = MagicMock(certificate=cert)
        self.charm.tls._on_certificate_invalidated(event_mock)

        request_certificate_renewal.assert_called_once()

    # Testing store_new_ca() function

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_truststore_password_secret(
        self, _, __, _create_keystore_pwd_if_not_exists, deployment_desc
    ):
        deployment_desc.return_value = self.deployment_descriptions["ok"]
        secret = {"key": "secret_12345"}

        self.harness.set_leader(is_leader=False)
        self.charm.tls.store_new_ca(secret)

        _create_keystore_pwd_if_not_exists.assert_not_called()

        self.harness.set_leader(is_leader=True)
        self.charm.tls.store_new_ca(secret)

        _create_keystore_pwd_if_not_exists.assert_called_once()

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_truststore_password_secret_only_created_by_main_orchestrator(
        self, _, __, _create_keystore_pwd_if_not_exists, deployment_desc
    ):
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.OTHER,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        secret = {"key": "secret_12345"}

        self.harness.set_leader(is_leader=True)
        self.charm.tls.store_new_ca(secret)

        _create_keystore_pwd_if_not_exists.assert_not_called()

    ##########################################################################
    # Full workflow tests
    ##########################################################################

    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_leader_app_cert_full_workflow(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        _read_stored_ca,
        deployment_desc,
        run_cmd,
    ):
        """New certificate received.

        The charm leader unit should save the new certificate both to
        Juju secrets and to the keystore.

        Applies to:
         - all deployments
         - leader ONLY
        """
        csr = "csr"
        key = "key"
        ca = "ca"

        new_cert = "new_cert"
        new_chain = ["new_chain"]

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": csr,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
            },
        )
        # Purposefully not adding unit certificates, to also trigger corner-case checks

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=new_chain, certificate=new_cert, ca=ca
        )

        # There was no change of the CA (certificate), the event matches the one on disk
        _read_stored_ca.return_value = ca

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )

        self.harness.set_leader(is_leader=True)

        original_status_app = self.harness.model.app.status
        original_status_unit = self.harness.model.unit.status
        self.charm._restart_opensearch_event = MagicMock()

        self.charm.tls._on_certificate_available(event_mock)

        # The new cert is saved to the keystore
        # NOTE on the leader node, the operation is redundant i.e. executed TWICE
        # This is because the function that applies on normal units to save app certificate
        # is executed on top of the mechanism that recognizes that the leader
        # received a new app cert
        assert run_cmd.call_count == 4

        assert re.search(
            "openssl pkcs12 -export .*-out "
            "/var/snap/opensearch/current/etc/opensearch/certificates/app-admin.p12 .*-name app-admin",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            "sudo chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/app-admin.p12"
            in run_cmd.call_args_list[1].args[0]
        )

        assert self.harness.model.app.status == original_status_app
        assert self.harness.model.unit.status == original_status_unit

        # The new certificate is now replacing the old one in Peer Relation secrets
        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": csr,
            "key": key,
            "ca-cert": ca,
            "cert": new_cert,
            "chain": new_chain[0],
            "truststore-password": "truststore_12345",
            "keystore-password": "keystore_12345",
        }

    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        itertools.product(
            [
                (DeploymentType.MAIN_ORCHESTRATOR),
                (DeploymentType.OTHER),
                (DeploymentType.FAILOVER_ORCHESTRATOR),
            ],
            [True, False],
            [CertType.UNIT_HTTP.val, CertType.UNIT_TRANSPORT.val],
        )
    )
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_any_node_unit_cert_full_workflow(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        leader,
        cert_type,
        _,
        _read_stored_ca,
        deployment_desc,
        run_cmd,
    ):
        """New *unit* certificate received.

        At this point the charm leader unit should save the new certificate both to
        Juju secrets and to the keystore.

        Applies to:
         - all deployments
         - all units
        """
        csr = "csr"
        key = "key"
        ca = "ca"
        keystore_password = "keystore_12345"

        new_cert = "new_cert"
        new_chain = ["new_chain"]

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": csr,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
                "keystore-password": keystore_password,
                "truststore-password": "truststore_12345",
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT,
            {
                "csr": f"{CertType.UNIT_TRANSPORT.val}-csr",
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
            },
        )

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP,
            {
                "csr": f"{CertType.UNIT_HTTP.val}-csr",
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
            },
        )

        event_mock = MagicMock(
            certificate_signing_request=f"{cert_type}-csr",
            chain=new_chain,
            certificate=new_cert,
            ca=ca,
        )

        # There was no change of the CA (certificate), the event matches the one on disk
        _read_stored_ca.return_value = ca

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )

        self.harness.set_leader(is_leader=leader)

        original_status_unit = self.harness.model.unit.status
        self.charm._restart_opensearch_event = MagicMock()

        self.charm.tls._on_certificate_available(event_mock)

        # The new cert is saved to the keystore
        assert run_cmd.call_count == 2

        assert re.search(
            "openssl pkcs12 -export .*-out "
            f"/var/snap/opensearch/current/etc/opensearch/certificates/{cert_type}.p12 .*-name {cert_type}",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            f"sudo chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/{cert_type}.p12"
            in run_cmd.call_args_list[1].args[0]
        )

        assert self.harness.model.unit.status == original_status_unit

        # The new certificate is now replacing the old one in Peer Relation secrets
        assert self.secret_store.get_object(Scope.UNIT, cert_type) == {
            "csr": f"{cert_type}-csr",
            "key": key,
            "ca-cert": ca,
            "cert": new_cert,
            "chain": new_chain[0],
            "keystore-password": keystore_password,
            "truststore-password": "truststore_12345",
        }

    ##########################################################################
    # Tests below verify to the CA rotation cycle
    ##########################################################################

    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_ca_rotation_first_stage_any_cluster_leader(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        deployment_desc,
        _read_stored_ca,
        run_cmd,
    ):
        """Test CA rotation 1st stage.

        At this point the charm already is receiving a new CA cert from the
        'self-signed-certificates' charm.
        Note: there is no preceding action on any of the involved parties to trigger that.
        The new CA cert may be received due to a CA change, CA cert expiration, etc.
        The 'self-signed-certificates' operator sends no signal/notification but simply adds
        the new CA certificate to a 'certificate-available' event.

        On this event, the Opensearch charm should:
         - save the new CA cert to truststore ALONGSIDE the old one that receives a new alias
         - set the 'tls_ca_renewing' flag in the peer databag
         - trigger a service restart
         - set the charm state to 'maintenance', indicating CA certificate rotation

        NOTE: The 'certificate-available' event also contains a new cert and chain. These are
        kind of "useless", as will need to request new ones matching the new CA cert.
        Not to modify existing workflows, they are saved to the secret but NOT to the disk.
        (The inconsistency is temporary, while the charm is in a maintenance mode anyway.)

        Applies to
         - any deployment types
         - leader ONLY
           - normal units are passive, see test later
        """
        old_csr = "old_csr"

        new_cert = "new_cert"
        new_chain = ["new_chain"]
        new_ca = "new_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": old_csr,
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            },
        )

        # NOTE: The event is issued with the old csr, i.e. the identifier of
        # the ongoing transaction. A new csr will be generated and saved in the second step
        event_mock = MagicMock(
            certificate_signing_request=old_csr, chain=new_chain, certificate=new_cert, ca=new_ca
        )

        # The CA stored in the keystore is still the old one
        _read_stored_ca.return_value = "old_ca"

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )

        self.charm._restart_opensearch_event = MagicMock()

        self.harness.set_leader(is_leader=True)
        original_status = self.harness.model.unit.status

        self.charm.tls._on_certificate_available(event_mock)

        # Old CA cert is saved with corresponding alias, new new CA cert added to keystore
        assert run_cmd.call_count == 3
        assert re.search(
            "keytool *-changealias *-alias ca *-destalias old-ca",
            run_cmd.call_args_list[0].args[0],
        )
        assert re.search("keytool *-importcert.* *-alias ca", run_cmd.call_args_list[1].args[0])
        assert (
            "chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/ca.p12"
            in run_cmd.call_args_list[2].args[0]
        )
        # NOTE: The new cert and chain are NOT saved into the keystore (disk)

        # Set flag, set status, restart
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewing"]
            == "True"
        )
        assert isinstance(self.harness.model.unit.status, MaintenanceStatus)
        assert self.harness.model.unit.status.message == TLSCaRotation
        assert self.harness.model.unit.status, MaintenanceStatus != original_status
        self.charm._restart_opensearch_event.emit.assert_called_once()

        # The new certificate is now replacing the old one in Peer Relation secrets
        # NOTE: INCONSISTENCY: The new cert and chain ARE saved into the secret
        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": old_csr,
            "cert": new_cert,
            "chain": new_chain[0],
            "truststore-password": "truststore_12345",
            "keystore-password": "keystore_12345",
            "ca-cert": new_ca,
        }

    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    def test_on_certificate_available_ca_rotation_first_stage_any_cluster_non_leader(
        # NOTE: Syntax: parametrized parameter comes first
        self,
        deployment_type,
        deployment_desc,
        _read_stored_ca,
        run_cmd,
    ):
        """'certificate-available' with an app cert and/or a CA cert.

        ONLY the leader takes action.
        """
        csr = "old_csr"
        cert = "new_cert"
        chain = ["new_chain"]
        ca = "new_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": csr,
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            },
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )

        _read_stored_ca.return_value = "stored_ca"

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )

        self.harness.set_leader(is_leader=False)
        original_status = self.harness.model.unit.status
        self.charm._restart_opensearch_event = MagicMock()

        self.charm.tls._on_certificate_available(event_mock)

        # No action taken, no change on status or certificates
        assert run_cmd.call_count == 0
        assert self.harness.model.unit.status == original_status
        self.charm._restart_opensearch_event.emit.assert_not_called()
        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": csr,
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
            "ca-cert": "old_ca_cert",
            "cert": "old_cert",
        }

    # Mocks on functions we want to investigate
    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_renewal"
    )
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_revocation"
    )
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_creation"
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Necessary mocks to simulate a smotth startup
    @patch("machine_upgrade.Upgrade")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("socket.socket.connect")
    @responses.activate
    def test_on_certificate_available_ca_rotation_second_stage_any_cluster_leader(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        __,
        upgrade,
        deployment_desc,
        _read_stored_ca,
        create_cert,
        revoke_cert,
        renew_cert,
        generate_csr,
    ):
        """Test CA rotation 2nd stage.

        At this point the charm already has the new CA cert stored locally
        (with the old CA cert also being kept around) and a service restart
        was supposed to take place.

        After the restart
         - old certificates have to be invalidated
         - unit certificates have to be renewed using the new CA cert
         - to signify the above being completed, the 'tls_ca_renewed' flag is set in the databag.

        Applies to
         - any deployment types
         - LEADER ONLY
        """
        # Units had their certificates already
        old_csr = "old_csr"
        old_key = create_utf8_encoded_private_key()
        old_subject = "old_subject"
        keystore_password = "keystore_12345"

        new_ca = "new_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": old_csr,
                "keystore-password": keystore_password,
                "truststore-password": "truststore_12345",
                "ca-cert": new_ca,
                "key": old_key,
                "subject": old_subject,
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT.val,
            {
                "keystore-password": keystore_password,
                "csr": "csr-transport",
                "key": "key-transport",
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP.val,
            {"keystore-password": keystore_password, "csr": "csr-http", "key": "key-http"},
        )

        # Leader ONLY
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            self.harness.update_relation_data(
                self.rel_id, "opensearch", {"security_index_initialised": "True"}
            )

            # We passed the 1st stage of the certificate renewalV
            self.harness.update_relation_data(
                self.rel_id, "opensearch/0", {"tls_ca_renewing": "True"}
            )

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        upgrade_mock = MagicMock(app_status=ActiveStatus())
        upgrade_mock.get_unit_juju_status.return_value = ActiveStatus()
        upgrade.return_value = upgrade_mock

        mock_response_root(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_nodes(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_lock_not_requested("1.1.1.1")
        mock_response_health_green("1.1.1.1")
        event = MagicMock(after_upgrade=False)
        original_status = self.harness.model.unit.status

        self.charm._post_start_init(event)

        # 'tls_ca_renewed' flag is set, new unit certificates were requested
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewed"] == "True"
        )

        new_app_admin_secret = self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val)

        assert new_app_admin_secret["csr"] != old_csr
        assert new_app_admin_secret["ca-cert"] == new_ca
        assert new_app_admin_secret["key"] == old_key
        assert new_app_admin_secret["subject"] != old_subject

        assert generate_csr.call_count == 3
        assert revoke_cert.called_with(
            private_key=bytes(new_app_admin_secret["csr"], encoding="utf-8")
        )
        assert revoke_cert.called_with(private_key=b"key-http")
        assert revoke_cert.called_with(private_key=b"key-transport")

        assert create_cert.call_count == 1
        assert create_cert.called_with(certificate_signing_request=new_app_admin_secret["csr"])

        assert revoke_cert.call_count == 2
        assert revoke_cert.called_with(b"csr-http")
        assert revoke_cert.called_with(b"csr-transport")

        assert renew_cert.call_count == 2
        assert renew_cert.called_with(old_certificate_signing_renew=b"csr-http")
        assert renew_cert.called_with(old_certificate_signing_renew=b"csr-transport")

        assert self.harness.model.unit.status.message == TLSNotFullyConfigured
        assert self.harness.model.unit.status, MaintenanceStatus != original_status

    # Mocks on functions we want to investigate
    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.generate_csr")
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_renewal"
    )
    @patch(
        "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3.request_certificate_revocation"
    )
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    # Necessary mocks to simulate a smooth startup
    @patch("machine_upgrade.Upgrade")
    @patch("socket.socket.connect")
    @responses.activate
    def test_on_certificate_available_ca_rotation_second_stage_any_cluster_non_leader(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        upgrade,
        _read_stored_ca,
        deployment_desc,
        revoke_cert,
        renew_cert,
        generate_csr,
    ):
        """Test CA rotation 2nd stage.

        At this point the charm already has the new CA cert stored locally
        (with the old CA cert also being kept around) and a service restart
        was supposed to take place.

        After the restart, unit certificates have to be renewed,
        and the 'tls_ca_renewed' flag has to be set in the databag.

        Applies to
         - any deployment types
         - any units
        """
        # Units had their certificates already
        csr = "old_csr"
        ca = "new_ca"
        keystore_password = "keystore_12345"

        csr_http_old = "csr-http-old"
        csr_transport_old = "csr-transport-old"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": csr,
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "ca-cert": ca,
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT.val,
            {
                "keystore-password": keystore_password,
                "csr": csr_transport_old,
                "key": "key-transport",
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP.val,
            {"keystore-password": keystore_password, "csr": csr_http_old, "key": "key-http"},
        )

        # Emphasizing: NON-leader
        self.harness.set_leader(is_leader=False)
        with self.harness.hooks_disabled():
            self.harness.update_relation_data(
                self.rel_id, "opensearch", {"security_index_initialised": "True"}
            )

            # We passed the 1st stage of the certificate renewalV
            self.harness.update_relation_data(
                self.rel_id, "opensearch/0", {"tls_ca_renewing": "True"}
            )

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        upgrade_mock = MagicMock(app_status=ActiveStatus())
        upgrade_mock.get_unit_juju_status.return_value = ActiveStatus()
        upgrade.return_value = upgrade_mock

        mock_response_root(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_nodes(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_lock_not_requested("1.1.1.1")
        mock_response_health_green("1.1.1.1")
        event = MagicMock(after_upgrade=False)
        original_status = self.harness.model.unit.status

        self.charm._post_start_init(event)

        # 'tls_ca_renewed' flag is set, new unit certificates were requested
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewed"] == "True"
        )
        # Note that the old flag is left intact
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewing"]
            == "True"
        )

        assert revoke_cert.call_count == 2
        assert revoke_cert.called_with(b"csr-http")
        assert revoke_cert.called_with(b"csr-transport")

        assert renew_cert.call_count == 2
        assert renew_cert.called_with(old_certificate_signing_renew=b"csr-http")
        assert renew_cert.called_with(old_certificate_signing_renew=b"csr-transport")

        assert (
            self.secret_store.get_object(Scope.UNIT, CertType.UNIT_HTTP.val)["csr"] != csr_http_old
        )
        assert (
            self.secret_store.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val)["csr"]
            != csr_transport_old
        )

        assert self.harness.model.unit.status.message == TLSNotFullyConfigured
        assert self.harness.model.unit.status, MaintenanceStatus != original_status

    # Mocks to investigate/compare/alter
    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_ca_rotation_third_stage_leader_cert_app(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        _read_stored_ca,
        deployment_desc,
        run_cmd,
    ):
        """Test CA rotation 3rd stage -- *app* certificate.

        At this point, the new CA has been already saved to the keystore.
        The charm receives the new app certificate. The leader unit has to save it.

        Applies to:

        """
        cert = "new_cert"
        chain = ["new_chain"]
        csr = "old_csr"
        ca = "new_ca"
        key = "key"
        keystore_password = "keystore_12345"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": csr,
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "ca-cert": ca,
                "key": key,
            },
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )

        # The new CA cert has been saved to the keystore earlier
        def mock_stored_ca(alias: str | None = None):
            if alias == "old-ca":
                return "old_ca_cert"
            return ca

        _read_stored_ca.side_effect = mock_stored_ca

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )

        self.charm._restart_opensearch_event = MagicMock()
        self.harness.model.unit.status = MaintenanceStatus()
        original_status = self.harness.model.unit.status

        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            self.harness.update_relation_data(
                self.rel_id, "opensearch", {"security_index_initialised": "True"}
            )

            # We passed the 1st stage of the certificate renewalV
            self.harness.update_relation_data(
                self.rel_id, "opensearch/0", {"tls_ca_renewing": "True", "tls_ca_renewed": "True"}
            )

        self.charm.tls._on_certificate_available(event_mock)

        # NOTE: Currently store_new_tls_resources() is invoked twice for 'app-admin' cert!
        assert run_cmd.call_count == 4

        # Exporting new certs
        assert re.search(
            "openssl pkcs12 -export .* -out "
            "/var/snap/opensearch/current/etc/opensearch/certificates/app-admin.p12 .* -name app-admin",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            "chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/app-admin.p12"
            in run_cmd.call_args_list[1].args[0]
        )
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewed"] == "True"
        )
        # Note that the old flag is left intact
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewing"]
            == "True"
        )

        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": csr,
            "cert": cert,
            "chain": chain[0],
            "truststore-password": "truststore_12345",
            "keystore-password": "keystore_12345",
            "key": key,
            "ca-cert": ca,
        }

        assert self.harness.model.unit.status.message == ""
        assert self.harness.model.unit.status, MaintenanceStatus != original_status

    # Mocks to investigate/compare/alter
    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        list(
            itertools.product(
                [
                    (DeploymentType.MAIN_ORCHESTRATOR),
                    (DeploymentType.OTHER),
                    (DeploymentType.FAILOVER_ORCHESTRATOR),
                ],
                [True, False],
                [CertType.UNIT_HTTP.val, CertType.UNIT_TRANSPORT.val],
            )
        )
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.reload_tls_certificates")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    @patch("charms.opensearch.v0.opensearch_tls.exists", return_value=True)
    @patch("opensearch.OpenSearchSnap.write_file")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    @patch("socket.socket.connect")
    @responses.activate
    def test_on_certificate_available_ca_rotation_third_stage_any_unit_cert_unit(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        leader,
        cert_type,
        _,
        __,
        ___,
        _____,
        _read_stored_ca,
        deployment_desc,
        run_cmd,
        reload_tls_certificates,
    ):
        """Test CA rotation 3rd stage -- *unit* certificate.

        At this point, the new CA has been already saved to the keystore.
        The charm receives a new unit certificate in the 'certificate-available' event.
        The unit has to
         1. save the new certificate
         2. if it was the last one to be updated: remove CA renewal flags
         3. if it was the last one updated: remove CA from keystore

        Applies to:
         - all deployments
         - all units
        """
        cert = "new_cert"
        chain = ["new_chain"]
        ca = "new_ca"
        key = "key"
        keystore_password = "keystore_12345"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": "new_csr",
                "keystore-password": keystore_password,
                "truststore-password": "truststore_12345",
                "ca-cert": ca,
                "cert": "cert",
                "key": "new_key",
                "subject": "new_subject",
                "chain": chain,
            },
        )

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT,
            {
                "csr": f"{CertType.UNIT_TRANSPORT.val}-csr-new",
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
            },
        )

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP,
            {
                "csr": f"{CertType.UNIT_HTTP.val}-csr-new",
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
            },
        )

        # The event is addressing the transaction identified by the new csr
        # for the corresponding cert type defined by the test parameter
        event_mock = MagicMock(
            certificate_signing_request=f"{cert_type}-csr-new",
            chain=chain,
            certificate=cert,
            ca=ca,
        )

        # The new CA cert has been saved to the keystore earlier
        _read_stored_ca.return_value = ca

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )

        self.charm._restart_opensearch_event = MagicMock()
        self.harness.model.unit.status = MaintenanceStatus()

        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=leader)
            self.harness.update_relation_data(
                self.rel_id,
                "opensearch",
                {"security_index_initialised": "True", "admin_user_initialized": "True"},
            )

            # We passed the 1st stage of the certificate renewalV
            self.harness.update_relation_data(
                self.rel_id, "opensearch/0", {"tls_ca_renewing": "True", "tls_ca_renewed": "True"}
            )

        reload_tls_certificates.side_effect = None
        mock_response_put_transport_cert("1.1.1.1")
        mock_response_put_http_cert("1.1.1.1")
        original_status = self.harness.model.unit.status

        self.charm.tls._on_certificate_available(event_mock)

        # Saving new cert, cleaning up CA renewal flag, removing old CA from keystore
        # Note: the high number of operations come from the fact that on each certificate received
        # the 'issuer' is checked on each certificate that is saved on the disk.
        if self.charm.unit.is_leader():
            assert run_cmd.call_count == 14
        else:
            assert run_cmd.call_count == 20

        assert re.search(
            "openssl pkcs12 -export .* -out "
            f"/var/snap/opensearch/current/etc/opensearch/certificates/{cert_type}.p12 .* -name {cert_type}",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            f"chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/{cert_type}.p12"
            in run_cmd.call_args_list[1].args[0]
        )
        assert re.search("keytool .*-delete .*-alias old-ca", run_cmd.call_args_list[-1].args[0])

        assert "tls_ca_renewing" not in self.harness.get_relation_data(self.rel_id, "opensearch/0")
        assert "tls_ca_renewed" not in self.harness.get_relation_data(self.rel_id, "opensearch/0")

        assert self.harness.model.unit.status.message == ""
        assert self.harness.model.unit.status, MaintenanceStatus != original_status

    # Additional potential phases of the workflow

    # Mock to investigate/compare/alter
    @parameterized.expand(
        list(
            itertools.product(
                [
                    (DeploymentType.MAIN_ORCHESTRATOR),
                    (DeploymentType.OTHER),
                    (DeploymentType.FAILOVER_ORCHESTRATOR),
                ],
                [True, False],
            )
        )
    )
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mock to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_rotation_ongoing_on_this_unit(
        # NOTE: Syntax: parametrized parameter comes first
        self,
        deployment_type,
        leader,
        _,
        _read_stored_ca,
        deployment_desc,
        run_cmd,
    ):
        """Additional 'certificate-available' event while processing CA rotation.

        In case any stage of a CA cert rotation is being processed,
        further 'certificate-available' events are deferred.

        Applies to:
         - any deployment
         - any unit
        """
        csr = "old_csr"
        cert = "new_cert"
        chain = ["new_chain"]
        ca = "new_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": csr,
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            },
        )

        _read_stored_ca.return_value = "stored_ca"

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )
        self.charm.on.certificate_available = MagicMock()

        self.harness.set_leader(is_leader=leader)
        original_status = self.harness.model.unit.status

        # This unit is within the process of certificate renewal
        with self.harness.hooks_disabled():
            self.harness.update_relation_data(
                self.rel_id, f"{self.charm.unit.name}", {"tls_ca_renewing": "True"}
            )

        self.charm.tls._on_certificate_available(event_mock)

        # No action taken, no change on status or certificates
        assert run_cmd.call_count == 0
        assert self.harness.model.unit.status == original_status
        self.charm.on.certificate_available.defer.called_once()
        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": csr,
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
            "ca-cert": "old_ca_cert",
            "cert": "old_cert",
        }

    # Mock to investigate/compare/alter
    @parameterized.expand(
        list(
            itertools.product(
                [
                    (DeploymentType.MAIN_ORCHESTRATOR),
                    (DeploymentType.OTHER),
                    (DeploymentType.FAILOVER_ORCHESTRATOR),
                ],
                [True, False],
            )
        )
    )
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mock to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._read_stored_ca")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_rotation_ongoing_on_another_unit(
        # NOTE: Syntax: parametrized parameter comes first
        self,
        deployment_type,
        leader,
        _,
        _read_stored_ca,
        deployment_desc,
        run_cmd,
    ):
        """Additional 'certificate-available' event while processing CA rotation.

        In case any stage of a CA cert rotation is being processed,
        further 'certificate-available' events are deferred.

        Applies to:
         - any deployment
         - any unit
        """
        csr = "old_csr"
        cert = "new_cert"
        chain = ["new_chain"]
        ca = "new_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": csr,
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            },
        )

        _read_stored_ca.return_value = "stored_ca"

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(cluster_name="", init_hold=False, roles=[]),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )
        self.charm.on.certificate_available = MagicMock()

        self.harness.set_leader(is_leader=leader)
        original_status = self.harness.model.unit.status

        # This unit has updated CA certificate
        # but another unit of the cluster is still within the process
        self.harness.add_relation_unit(self.rel_id, f"{self.charm.app.name}/1")
        with self.harness.hooks_disabled():
            self.harness.update_relation_data(
                self.rel_id, f"{self.charm.app.name}/0", {"tls_ca_renewed": "True"}
            )
            self.harness.update_relation_data(
                self.rel_id, f"{self.charm.app.name}/1", {"tls_ca_renewing": "True"}
            )

        self.charm.tls._on_certificate_available(event_mock)

        # No action taken, no change on status or certificates
        assert run_cmd.call_count == 0
        assert self.harness.model.unit.status == original_status
        self.charm.on.certificate_available.defer.called_once()
        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": csr,
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
            "ca-cert": "old_ca_cert",
            "cert": "old_cert",
        }
