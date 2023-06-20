# Copyright 2023 Canonical Ltd.
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
import glob
import json
import logging
import os
import re
import socket
import tempfile
from os.path import exists
from typing import Any, Dict, List, Optional, Tuple

from charms.opensearch.v0.constants_tls import TLS_RELATION, CertType
from charms.opensearch.v0.helper_commands import run_cmd
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.helper_networking import get_host_public_ip
from charms.opensearch.v0.helper_security import generate_password
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    TLSCertificatesRequiresV1,
    generate_csr,
    generate_private_key,
)
from ops.charm import (
    ActionEvent,
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationJoinedEvent,
)
from ops.framework import Object

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

    def __init__(self, charm, peer_relation: str, jdk_path: str, certs_path: str):
        super().__init__(charm, "client-relations")

        self.charm = charm
        self.peer_relation = peer_relation
        self.jdk_path = jdk_path
        self.certs_path = certs_path
        self.certs = TLSCertificatesRequiresV1(charm, TLS_RELATION)

        self.framework.observe(
            self.charm.on.set_tls_private_key_action, self._on_set_tls_private_key
        )

        self.framework.observe(
            self.charm.on[TLS_RELATION].relation_joined, self._on_tls_relation_joined
        )

        self.framework.observe(
            self.charm.on[TLS_RELATION].relation_changed, self._on_tls_relation_changed
        )

        self.framework.observe(
            self.charm.on[TLS_RELATION].relation_broken, self._on_tls_relation_broken
        )

        self.framework.observe(self.certs.on.certificate_available, self._on_certificate_available)
        self.framework.observe(self.certs.on.certificate_expiring, self._on_certificate_expiring)

    def _on_set_tls_private_key(self, event: ActionEvent) -> None:
        """Set the TLS private key, which will be used for requesting the certificate."""
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

    def request_new_unit_certificates(self) -> None:
        """Requests a new certificate with the given scope and type from the tls operator."""
        self._delete_tls_resources()

        for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT]:
            csr = self.charm.secrets.get_object(Scope.UNIT, cert_type.val)["csr"].encode("utf-8")
            self.certs.request_certificate_revocation(csr)

        # doing this sequentially (revoking -> requesting new ones), to avoid triggering
        # the "certificate available" callback with old certificates
        for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT]:
            secrets = self.charm.secrets.get_object(Scope.UNIT, cert_type.val)
            self._request_certificate_renewal(Scope.UNIT, cert_type, secrets)

    def reset_internal_state(self) -> None:
        """Removes tls_ca_renewing flag so new certificates can be generated."""
        if not self.charm.peers_data.get(Scope.UNIT, "tls_ca_renewing", False):
            # this means simple certificate creation, with no CA renewal
            return

        # this means that the unit certificates were generated, after a previous CA renewal.
        if self.charm.peers_data.get(Scope.UNIT, "tls_ca_renewed", False):
            self.charm.peers_data.delete(Scope.UNIT, "tls_ca_renewing")
            self.charm.peers_data.delete(Scope.UNIT, "tls_ca_renewed")
        else:
            # this means only the CA renewal completed, still need to create certificates
            self.charm.peers_data.put(Scope.UNIT, "tls_ca_renewed", True)

    def _on_tls_relation_joined(self, _: RelationJoinedEvent) -> None:
        """Request certificate when TLS relation joined."""
        self.charm.on_tls_relation_joined()

        if self.charm.unit.is_leader():
            # create passwords for both ca trust_store/admin key_store
            self._create_keystore_pwd_if_not_exists(Scope.APP, "ca")
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN.val)

            admin_cert = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN)
            if admin_cert is None or self.charm.peers_data.get(
                Scope.UNIT, "tls_rel_broken", False
            ):
                self._request_certificate(Scope.APP, CertType.APP_ADMIN)

        # create passwords for both unit-http/transport key_stores
        self._create_keystore_pwd_if_not_exists(Scope.UNIT, CertType.UNIT_TRANSPORT.val)
        self._create_keystore_pwd_if_not_exists(Scope.UNIT, CertType.UNIT_HTTP.val)

        self._request_certificate(Scope.UNIT, CertType.UNIT_TRANSPORT)
        self._request_certificate(Scope.UNIT, CertType.UNIT_HTTP)

    def _on_tls_relation_changed(self, event: RelationChangedEvent) -> None:
        tls_rel_data = event.relation.data[event.app]
        if not tls_rel_data:
            return

        certs = tls_rel_data.get("certificates")
        if not certs:
            return

        certs = json.loads(certs)
        if not certs:
            return

        for cert_entry in certs:
            if not cert_entry.get("revoked", False):
                return

        self.charm.on_tls_relation_joined()

        if self.charm.unit.is_leader():
            self._request_certificate(Scope.APP, CertType.APP_ADMIN)

        self._request_certificate(Scope.UNIT, CertType.UNIT_TRANSPORT)
        self._request_certificate(Scope.UNIT, CertType.UNIT_HTTP)

    def _on_tls_relation_broken(self, _: RelationBrokenEvent) -> None:
        """Notify the charm that the relation is broken."""
        self.charm.peers_data.put(Scope.UNIT, "tls_rel_broken", True)
        self.charm.on_tls_relation_broken()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:  # noqa
        """Enable TLS when TLS certificate available.

        CertificateAvailableEvents fire whenever a new certificate is created by the TLS charm.
        """
        # this means that the leader unit hasn't initialized the truststore password
        if not self.charm.secrets.get(Scope.APP, "keystore-password-ca"):
            event.defer()
            return

        # CA renewal still in progress (rolling restart)
        if self.charm.peers_data.get(
            Scope.UNIT, "tls_ca_renewing", False
        ) and not self.charm.peers_data.get(Scope.UNIT, "tls_ca_renewed", False):
            event.defer()
            return

        try:
            scope, cert_type, secrets = self._find_secret(event.certificate_signing_request, "csr")
            logger.debug(f"{scope.val}.{cert_type.val} TLS certificate available.")
        except TypeError:
            logger.debug("Unknown certificate available.")
            return

        # check if this is a new "ca", if it is - store it in the trust store
        current_stored_ca = self._read_stored_ca()
        if current_stored_ca != event.ca:
            self.store_new_ca(event.ca)

            # this means the CA is renewed - we need to restart all units with this new CA
            # prior to updating the certificates with the new CA.
            if current_stored_ca:
                self.charm.peers_data.put(Scope.UNIT, "tls_ca_renewing", True)
                self.charm.on_tls_ca_renewal(event)
                event.defer()
                return

        # seems like the admin certificate is also broadcast to non leader units on refresh request
        if not self.charm.unit.is_leader() and scope == Scope.APP:
            return

        # check if there was a CA renewal on the cluster, if not complete defer
        if not self._ca_renewal_complete_in_cluster():
            event.defer()
            return

        # check if certificate renewal
        old_cert = secrets.get("cert", None)
        cert_renewal = (
            self._read_stored_ca(alias="old-ca") is not None
            or (old_cert is not None and old_cert != event.certificate)
            or self.charm.peers_data.get(Scope.UNIT, "tls_rel_broken", False)
        )

        # persist the certificate on the secrets + disk
        self._persist_certificate(event, scope, cert_type)

        # store the admin certificates in non-leader units
        if not self.charm.unit.is_leader():
            if self.all_certificates_available():
                admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
                self._store_new_tls_resources(Scope.APP, CertType.APP_ADMIN, admin_secrets)
            elif self._unit_certificates_available():  # admin certificate not ready yet
                # we defer the last certificate available event
                event.defer()
                return

        self.charm.on_tls_conf_set(event, scope, cert_type, cert_renewal)

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """Request the new certificate when old certificate is expiring."""
        try:
            scope, cert_type, secrets = self._find_secret(event.certificate, "cert")
            logger.debug(f"{scope.val}.{cert_type.val} TLS certificate expiring.")
        except TypeError:
            logger.debug("Unknown certificate expiring.")
            return

        self._request_certificate_renewal(scope, cert_type, secrets)

    def _persist_certificate(
        self, event: CertificateAvailableEvent, scope: Scope, cert_type: CertType
    ) -> None:
        """Persist the certificate on the secrets store and on disk."""
        self.charm.secrets.put_object(
            scope,
            cert_type.val,
            {
                "cert": event.certificate,
                "cert-chain": event.chain[::-1],
                "ca": event.ca,
            },
            merge=True,
        )

        # store the certificates and keys in a key store
        self._store_new_tls_resources(
            scope, cert_type, self.charm.secrets.get_object(scope, cert_type.val)
        )

        # set flag to indicate cert type well configured
        if self.charm.unit.is_leader() and cert_type == CertType.APP_ADMIN:
            self.charm.peers_data.put(Scope.APP, f"tls_{cert_type}_configured", True)
        else:
            self.charm.peers_data.put(Scope.UNIT, f"tls_{cert_type}_configured", True)

    def _request_certificate(
        self,
        scope: Scope,
        cert_type: CertType,
        key: Optional[str] = None,
        password: Optional[str] = None,
    ):
        """Request certificate and store the key/key-password/csr in the scope's data bag."""
        # self._request_certificate_revocation(cert_type)
        self.charm.peers_data.put(
            Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT,
            f"tls_{cert_type}_configured",
            False,
        )
        # self._delete_tls_resources()

        if key is None:
            key = generate_private_key()
        else:
            key = self._parse_tls_file(key)

        if password is not None:
            password = password.encode("utf-8")

        subject = self._get_subject(cert_type)
        csr = generate_csr(
            add_unique_id_to_subject_name=False,
            private_key=key,
            private_key_password=password,
            subject=subject,
            organization=self.charm.app.name,
            **self._get_sans(cert_type),
        )

        self.charm.secrets.put_object(
            scope,
            cert_type.val,
            {
                "key": key.decode("utf-8"),
                "key-password": password,
                "csr": csr.decode("utf-8"),
                "subject": f"/O={self.charm.app.name}/CN={subject}",
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
        new_csr = generate_csr(
            private_key=key,
            private_key_password=(None if key_password is None else key_password.encode("utf-8")),
            subject=subject,
            organization=self.charm.app.name,
            **self._get_sans(cert_type),
        )

        self.charm.secrets.put_object(
            scope, cert_type.val, {"csr": new_csr.decode("utf-8"), "subject": subject}, merge=True
        )

        self.certs.request_certificate_renewal(
            old_certificate_signing_request=old_csr,
            new_certificate_signing_request=new_csr,
        )

    def _request_certificate_revocation(self, cert_type: CertType):
        """Requests the revocation of a certificate."""
        existing_secrets = self.charm.secrets.get_object(Scope.UNIT, cert_type.val)
        if existing_secrets:
            self.certs.request_certificate_revocation(existing_secrets["csr"].encode("utf-8"))

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

    def _unit_certificates_available(self) -> bool:
        """Method that checks if all units related certificates in secrets store."""
        secrets = self.charm.secrets

        cert_cas = set()
        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            unit_secrets = secrets.get_object(Scope.UNIT, cert_type.val)
            if not unit_secrets or not unit_secrets.get("cert"):
                return False

            cert_cas.add(unit_secrets.get("ca"))

        return len(cert_cas) == 1

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

        peers_data = self.charm.peers_data
        return (
            peers_data.get(Scope.APP, f"tls_{CertType.APP_ADMIN}_configured", False)
            and peers_data.get(Scope.UNIT, f"tls_{CertType.UNIT_TRANSPORT}_configured", False)
            and peers_data.get(Scope.UNIT, f"tls_{CertType.UNIT_HTTP}_configured", False)
        )

    def all_tls_resources_stored(self, only_unit_resources: bool = False) -> bool:
        """Check if all TLS resources are stored on disk."""
        cert_types = ["ca", CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]
        if not only_unit_resources:
            cert_types.append(CertType.APP_ADMIN)

        for cert_type in cert_types:
            if not exists(f"{self.certs_path}/{cert_type}.p12"):
                return False

        return True

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

    def remove_old_ca_if_any(self) -> None:
        """Remove old CA cert from trust store."""
        keytool = f"sudo {self.jdk_path}/bin/keytool"
        store_path = f"{self.certs_path}/ca.p12"
        old_alias = "old-ca"

        store_pwd = self.charm.secrets.get(Scope.APP, "keystore-password-ca")
        try:
            run_cmd(
                f"{keytool} -list -keystore {store_path} -storepass {store_pwd} -alias {old_alias} -storetype PKCS12"
            )
        except OpenSearchCmdError as e:
            # This message means there was no "ca" alias or store before, if it happens ignore
            if f"Alias <{old_alias}> does not exist" in e.out:
                return

        self._remove_key_store_content_by_alias(store_pwd, alias=old_alias, key_store_name="ca")

    def _store_new_tls_resources(self, scope: Scope, cert_type: CertType, secrets: Dict[str, Any]):
        """Add key and cert to keystore."""
        store_pwd = self.charm.secrets.get(scope, f"keystore-password-{cert_type.val}")
        store_path = f"{self.certs_path}/{cert_type.val}.p12"

        # we store the pem format to make it easier for the python requests lib
        if cert_type == CertType.APP_ADMIN:
            with open(f"{self.certs_path}/admin-cert-chain.pem", "w+") as f:
                f.write("\n".join(secrets.get("cert-chain")))

        # self._remove_key_store_content_by_alias(store_pwd, alias=cert_type.val)
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

    def _remove_key_store_content_by_alias(
        self, store_pass: str, alias: str, key_store_name: Optional[str] = None
    ):
        """Remove the resources matching an alias in a keystore."""
        if not key_store_name:
            key_store_name = alias

        keytool = f"sudo {self.jdk_path}/bin/keytool"
        try:
            run_cmd(
                f"""{keytool} -delete \
                -alias {alias} \
                -storepass {store_pass} \
                -keystore {self.certs_path}/{key_store_name}.p12
            """
            )
        except OpenSearchCmdError as e:
            # This message means there was no "<alias>" or store before, if it happens ignore
            if not (
                f"Alias <{alias}> does not exist" in e.out
                or "Keystore file does not exist" in e.out
            ):
                raise

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

    def _delete_tls_resources(self):
        """Delete all TLS resources in the current unit."""
        key_stores = glob.glob(f"{self.certs_path}/*")
        for key_store in key_stores:
            os.remove(key_store)

    def _ca_renewal_complete_in_cluster(self) -> bool:
        """Check whether the CA renewal completed in all units."""
        rel = self.charm.model.get_relation(self.peer_relation)
        for unit in rel.units.union({self.charm.unit}):
            rel_data = rel.data[unit]
            ca_renewing = rel_data.get("tls_ca_renewing")
            ca_renewed = rel_data.get("tls_ca_renewed")
            if ca_renewing == "True" and ca_renewed != "True":
                return False

        return True
