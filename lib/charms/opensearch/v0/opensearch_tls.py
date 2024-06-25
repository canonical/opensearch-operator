# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class we manage certificates relation.

This class handles certificate request and renewal through
the interaction with the TLS Certificates Operator.

This library needs https://charmhub.io/tls-certificates-interface/libraries/tls_certificates
library is imported to work.

It requires a charm that extends OpenSearchBaseCharm as it refers internal objects of that class.
— update_config: to disable TLS when relation with the TLS Certificates Operator is broken.
"""

import base64
import logging
import os
import re
import socket
import tempfile
import typing
from os.path import exists
from typing import Any, Dict, List, Optional, Tuple, Union

from charms.opensearch.v0.constants_tls import TLS_RELATION, CertType
from charms.opensearch.v0.helper_networking import get_host_public_ip
from charms.opensearch.v0.helper_security import generate_password, run_cmd
from charms.opensearch.v0.models import DeploymentType
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    TLSCertificatesRequiresV3,
    generate_csr,
    generate_private_key,
)
from ops.charm import ActionEvent, RelationBrokenEvent, RelationCreatedEvent
from ops.framework import Object

if typing.TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

# The unique Charmhub library identifier, never change it
LIBID = "8bcf275287ad486db5f25a1dbb26f920"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


class OpenSearchTLS(Object):
    """Class that Manages OpenSearch relation with TLS Certificates Operator."""

    def __init__(
        self, charm: "OpenSearchBaseCharm", peer_relation: str, jdk_path: str, certs_path: str
    ):
        super().__init__(charm, "tls-component")

        self.charm = charm
        self.peer_relation = peer_relation
        self.jdk_path = jdk_path
        self.certs_path = certs_path
        self.certs = TLSCertificatesRequiresV3(charm, TLS_RELATION)

        self.framework.observe(
            self.charm.on.set_tls_private_key_action, self._on_set_tls_private_key
        )

        self.framework.observe(
            self.charm.on[TLS_RELATION].relation_created, self._on_tls_relation_created
        )
        self.framework.observe(
            self.charm.on[TLS_RELATION].relation_broken, self._on_tls_relation_broken
        )

        self.framework.observe(self.certs.on.certificate_available, self._on_certificate_available)
        self.framework.observe(self.certs.on.certificate_expiring, self._on_certificate_expiring)
        self.framework.observe(
            self.certs.on.certificate_invalidated, self._on_certificate_invalidated
        )

    def _on_set_tls_private_key(self, event: ActionEvent) -> None:
        """Set the TLS private key, which will be used for requesting the certificate."""
        if self.charm.upgrade_in_progress:
            event.fail("Setting private key not supported while upgrade in-progress")
            return
        cert_type = CertType(event.params["category"])  # type
        scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT

        if scope == Scope.APP and not self.charm.unit.is_leader():
            event.log("Only the juju leader unit can set private key for the admin certificates.")
            return

        try:
            self._request_certificate(
                scope, cert_type, event.params.get("key", None), event.params.get("password", None)
            )
        except ValueError as e:
            event.fail(str(e))

    def request_new_admin_certificate(self) -> None:
        """Request the generation of a new admin certificate."""
        if not self.charm.unit.is_leader():
            return

        self._request_certificate(Scope.APP, CertType.APP_ADMIN)

    def request_new_unit_certificates(self) -> None:
        """Requests a new certificate with the given scope and type from the tls operator."""
        self.charm.peers_data.delete(Scope.UNIT, "tls_configured")

        for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT]:
            csr = self.charm.secrets.get_object(Scope.UNIT, cert_type.val)["csr"].encode("utf-8")
            self.certs.request_certificate_revocation(csr)

        # doing this sequentially (revoking -> requesting new ones), to avoid triggering
        # the "certificate available" callback with old certificates
        for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT]:
            secrets = self.charm.secrets.get_object(Scope.UNIT, cert_type.val)
            self._request_certificate_renewal(Scope.UNIT, cert_type, secrets)

    def _on_tls_relation_created(self, event: RelationCreatedEvent) -> None:
        """Request certificate when TLS relation created."""
        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )
            event.defer()
            return
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            event.defer()
            return
        admin_cert = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        if self.charm.unit.is_leader():
            # create passwords for both ca trust_store/admin key_store
            self._create_keystore_pwd_if_not_exists(Scope.APP, "ca")
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN.val)

            if admin_cert is None and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
                self._request_certificate(Scope.APP, CertType.APP_ADMIN)

        # create passwords for both unit-http/transport key_stores
        self._create_keystore_pwd_if_not_exists(Scope.UNIT, CertType.UNIT_TRANSPORT.val)
        self._create_keystore_pwd_if_not_exists(Scope.UNIT, CertType.UNIT_HTTP.val)

        self._request_certificate(Scope.UNIT, CertType.UNIT_TRANSPORT)
        self._request_certificate(Scope.UNIT, CertType.UNIT_HTTP)

    def _on_tls_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Notify the charm that the relation is broken."""
        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )
        self.charm.on_tls_relation_broken(event)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Enable TLS when TLS certificate available.

        CertificateAvailableEvents fire whenever a new certificate is created by the TLS charm.
        """
        try:
            scope, cert_type, secrets = self._find_secret(event.certificate_signing_request, "csr")
            logger.debug(f"{scope.val}.{cert_type.val} TLS certificate available.")
        except TypeError:
            logger.debug("Unknown certificate available.")
            return

        # seems like the admin certificate is also broadcast to non leader units on refresh request
        if not self.charm.unit.is_leader() and scope == Scope.APP:
            return

        old_cert = secrets.get("cert", None)
        renewal = old_cert is not None and old_cert != event.certificate

        ca_chain = "\n".join(event.chain[::-1])

        self.charm.secrets.put_object(
            scope,
            cert_type.val,
            {
                "chain": ca_chain,
                "cert": event.certificate,
                "ca-cert": event.ca,
            },
            merge=True,
        )

        # currently only make sure there is a CA
        # workflow for replacement will be added later
        if self._read_stored_ca() is None:
            self.store_new_ca(event.ca)

        # store the certificates and keys in a key store
        self.store_new_tls_resources(
            scope, cert_type, self.charm.secrets.get_object(scope, cert_type.val)
        )

        # store the admin certificates in non-leader units
        if not self.charm.unit.is_leader():
            if self.all_certificates_available():
                admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
                self.store_new_tls_resources(Scope.APP, CertType.APP_ADMIN, admin_secrets)

        for relation in self.charm.opensearch_provider.relations:
            self.charm.opensearch_provider.update_certs(relation.id, ca_chain)

        try:
            self.charm.on_tls_conf_set(event, scope, cert_type, renewal)
        except OpenSearchError as e:
            logger.exception(e)
            event.defer()

    def _on_certificate_expiring(
        self, event: Union[CertificateExpiringEvent, CertificateInvalidatedEvent]
    ) -> None:
        """Request the new certificate when old certificate is expiring."""
        self.charm.peers_data.delete(Scope.UNIT, "tls_configured")
        try:
            scope, cert_type, secrets = self._find_secret(event.certificate, "cert")
            logger.debug(f"{scope.val}.{cert_type.val} TLS certificate expiring.")
        except TypeError:
            logger.debug("Unknown certificate expiring.")
            return

        self._request_certificate_renewal(scope, cert_type, secrets)

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent) -> None:
        """Handle a cert that was revoked or has expired"""
        logger.debug(f"Received certificate invalidation. Reason: {event.reason}")
        self._on_certificate_expiring(event)

    def _request_certificate(
        self,
        scope: Scope,
        cert_type: CertType,
        key: Optional[str] = None,
        password: Optional[str] = None,
    ):
        """Request certificate and store the key/key-password/csr in the scope's data bag."""
        if key is None:
            key = generate_private_key()
        else:
            key = self._parse_tls_file(key)

        if password is not None:
            password = password.encode("utf-8")

        subject = self._get_subject(cert_type)
        organization = self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name
        csr = generate_csr(
            add_unique_id_to_subject_name=False,
            private_key=key,
            private_key_password=password,
            subject=subject,
            organization=organization,
            **self._get_sans(cert_type),
        )

        self.charm.secrets.put_object(
            scope=scope,
            key=cert_type.val,
            value={
                "key": key.decode("utf-8"),
                "key-password": password,
                "csr": csr.decode("utf-8"),
                "subject": f"/O={self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name}/CN={subject}",
            },
            merge=True,
        )

        if self.charm.model.get_relation(TLS_RELATION):
            self.certs.request_certificate_creation(certificate_signing_request=csr)

    def _request_certificate_renewal(
        self, scope: Scope, cert_type: CertType, secrets: Dict[str, str]
    ):
        """Request new certificate and store the key/key-password/csr in the scope's data bag."""
        key = secrets["key"].encode("utf-8")
        key_password = secrets.get("key-password", None)
        old_csr = secrets["csr"].encode("utf-8")

        subject = self._get_subject(cert_type)
        organization = self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name
        new_csr = generate_csr(
            private_key=key,
            private_key_password=(None if key_password is None else key_password.encode("utf-8")),
            subject=subject,
            organization=organization,
            **self._get_sans(cert_type),
        )

        self.charm.secrets.put_object(
            scope, cert_type.val, {"csr": new_csr.decode("utf-8"), "subject": subject}, merge=True
        )

        self.certs.request_certificate_renewal(
            old_certificate_signing_request=old_csr,
            new_certificate_signing_request=new_csr,
        )

    def _get_sans(self, cert_type: CertType) -> Dict[str, List[str]]:
        """Create a list of OID/IP/DNS names for an OpenSearch unit.

        Returns:
            A list representing the hostnames of the OpenSearch unit.
            or None if admin cert_type, because that cert is not tied to a specific host.
        """
        sans = {"sans_oid": ["1.2.3.4.5.5"]}  # required for node discovery
        if cert_type == CertType.APP_ADMIN:
            return sans

        dns = {self.charm.unit_name, socket.gethostname(), socket.getfqdn()}
        ips = {self.charm.unit_ip}

        host_public_ip = get_host_public_ip()
        if cert_type == CertType.UNIT_HTTP and host_public_ip:
            ips.add(host_public_ip)

        for ip in ips.copy():
            try:
                name, aliases, addresses = socket.gethostbyaddr(ip)
                ips.update(addresses)

                dns.add(name)
                dns.update(aliases)
            except (socket.herror, socket.gaierror):
                continue

        sans["sans_ip"] = [ip for ip in ips if ip.strip()]
        sans["sans_dns"] = [entry for entry in dns if entry.strip()]

        return sans

    def _get_subject(self, cert_type: CertType) -> str:
        """Get subject of the certificate."""
        if cert_type == CertType.APP_ADMIN:
            cn = "admin"
        else:
            cn = self.charm.unit_ip

        return cn

    @staticmethod
    def _parse_tls_file(raw_content: str) -> bytes:
        """Parse TLS files from both plain text or base64 format."""
        if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", raw_content):
            return re.sub(
                r"(-+(BEGIN|END) [A-Z ]+-+)",
                "\\1",
                raw_content,
            ).encode("utf-8")
        return base64.b64decode(raw_content)

    def _find_secret(
        self, event_data: str, secret_name: str
    ) -> Optional[Tuple[Scope, CertType, Dict[str, str]]]:
        """Find secret across all scopes (app, unit) and across all cert types.

        Returns:
            scope: scope type of the secret.
            cert type: certificate type of the secret (APP_ADMIN, UNIT_HTTP etc.)
            secret: dictionary of the data stored in this secret
        """

        def is_secret_found(secrets: Optional[Dict[str, str]]) -> bool:
            return (
                secrets is not None
                and secrets.get(secret_name, "").rstrip() == event_data.rstrip()
            )

        app_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        if is_secret_found(app_secrets):
            return Scope.APP, CertType.APP_ADMIN, app_secrets

        u_transport_secrets = self.charm.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val
        )
        if is_secret_found(u_transport_secrets):
            return Scope.UNIT, CertType.UNIT_TRANSPORT, u_transport_secrets

        u_http_secrets = self.charm.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP.val)
        if is_secret_found(u_http_secrets):
            return Scope.UNIT, CertType.UNIT_HTTP, u_http_secrets

        return None

    def get_unit_certificates(self) -> Dict[CertType, str]:
        """Retrieve the list of certificates for this unit."""
        certs = {}

        transport_secrets = self.charm.secrets.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val)
        if transport_secrets and transport_secrets.get("cert"):
            certs[CertType.UNIT_TRANSPORT] = transport_secrets["cert"]

        http_secrets = self.charm.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP.val)
        if http_secrets and http_secrets.get("cert"):
            certs[CertType.UNIT_HTTP] = http_secrets["cert"]

        if self.charm.unit.is_leader():
            admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
            if admin_secrets and admin_secrets.get("cert"):
                certs[CertType.APP_ADMIN] = admin_secrets["cert"]

        return certs

    def _create_keystore_pwd_if_not_exists(self, scope: Scope, alias: str):
        """Create passwords for the key stores if not already created."""
        keystore_pwd = self.charm.secrets.get(scope, f"keystore-password-{alias}")
        if not keystore_pwd:
            self.charm.secrets.put(scope, f"keystore-password-{alias}", generate_password())

    def store_new_ca(self, ca_cert: str):
        """Add new CA cert to trust store."""
        store_pwd = self.charm.secrets.get(Scope.APP, "keystore-password-ca")

        keytool = f"sudo {self.jdk_path}/bin/keytool"
        alias = "ca"
        store_path = f"{self.certs_path}/{alias}.p12"
        try:
            run_cmd(
                f"""{keytool} -changealias \
                -alias {alias} \
                -destalias old-{alias} \
                -keystore {store_path} \
                -storepass {store_pwd} \
                -storetype PKCS12
            """
            )
        except OpenSearchCmdError as e:
            # This message means there was no "ca" alias or store before, if it happens ignore
            if not (
                f"Alias <{alias}> does not exist" in e.out
                or "Keystore file does not exist" in e.out
            ):
                raise

        with tempfile.NamedTemporaryFile(mode="w+t") as ca_tmp_file:
            ca_tmp_file.write(ca_cert)
            ca_tmp_file.flush()

            run_cmd(
                f"""{keytool} -importcert \
                -trustcacerts \
                -noprompt \
                -alias {alias} \
                -keystore {store_path} \
                -file {ca_tmp_file.name} \
                -storepass {store_pwd} \
                -storetype PKCS12
            """
            )

        run_cmd(f"sudo chown -R snap_daemon:root {self.certs_path}")
        run_cmd(f"sudo chmod +r {store_path}")
        run_cmd(
            f"{keytool} -list -v -keystore {store_path} -storepass {store_pwd} -storetype PKCS12"
        )

    def _read_stored_ca(self, alias: str = "ca") -> Optional[str]:
        """Load stored CA cert."""
        store_pwd = self.charm.secrets.get(Scope.APP, "keystore-password-ca")

        ca_trust_store = f"{self.certs_path}/ca.p12"
        if not exists(ca_trust_store):
            return None

        stored_certs = run_cmd(f"openssl pkcs12 -in {ca_trust_store} -passin pass:{store_pwd}").out

        # parse output to retrieve the current CA (in case there are many)
        start_cert_marker = "-----BEGIN CERTIFICATE-----"
        end_cert_marker = "-----END CERTIFICATE-----"
        certificates = stored_certs.split(end_cert_marker)
        for cert in certificates:
            if f"friendlyName: {alias}" in cert:
                return f"{start_cert_marker}{cert.split(start_cert_marker)[1]}{end_cert_marker}"

        return None

    def store_new_tls_resources(self, scope: Scope, cert_type: CertType, secrets: Dict[str, Any]):
        """Add key and cert to keystore."""
        store_pwd = self.charm.secrets.get(Scope.APP, f"keystore-password-{cert_type.val}")
        store_path = f"{self.certs_path}/{cert_type}.p12"

        if not secrets.get("key"):
            logging.error("TLS key not found, quitting.")
            return

        # we store the pem format to make it easier for the python requests lib
        if cert_type == CertType.APP_ADMIN:
            with open(f"{self.certs_path}/admin-cert-chain.pem", "w+") as f:
                f.write("\n".join(secrets.get("cert-chain")))

        try:
            os.remove(store_path)
        except OSError:
            pass

        tmp_key = tempfile.NamedTemporaryFile(mode="w+t", suffix=".pem")
        tmp_key.write(secrets.get("key"))
        tmp_key.flush()
        tmp_key.seek(0)

        tmp_cert = tempfile.NamedTemporaryFile(mode="w+t", suffix=".cert")
        tmp_cert.write(secrets.get("cert"))
        tmp_cert.flush()
        tmp_cert.seek(0)

        try:
            cmd = f"""openssl pkcs12 -export \
                -in {tmp_cert.name} \
                -inkey {tmp_key.name} \
                -out {store_path} \
                -name {cert_type.val} \
                -passout pass:{store_pwd}
            """
            if secrets.get("key-password"):
                cmd = f"{cmd} -passin pass:{secrets.get('key-password')}"

            run_cmd(cmd)
            run_cmd(f"sudo chown -R snap_daemon:root {self.certs_path}")
            run_cmd(f"sudo chmod +r {store_path}")
        finally:
            tmp_key.close()
            tmp_cert.close()

    def all_tls_resources_stored(self, only_unit_resources: bool = False) -> bool:
        """Check if all TLS resources are stored on disk."""
        cert_types = ["ca", CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]
        if not only_unit_resources:
            cert_types.append(CertType.APP_ADMIN)

        for cert_type in cert_types:
            if not exists(f"{self.certs_path}/{cert_type}.p12"):
                return False

        return True

    def all_certificates_available(self) -> bool:
        """Method that checks if all certs available and issued from same CA."""
        secrets = self.charm.secrets

        admin_secrets = secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        if not admin_secrets or not admin_secrets.get("cert"):
            return False

        admin_ca = admin_secrets.get("ca")

        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            unit_secrets = secrets.get_object(Scope.UNIT, cert_type.val)
            if (
                not unit_secrets
                or not unit_secrets.get("cert")
                or unit_secrets.get("ca") != admin_ca
            ):
                return False

        return True
