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
from typing import Dict, List, Optional, Tuple

from charms.opensearch.v0.constants_tls import TLS_RELATION, CertType
from charms.opensearch.v0.helper_commands import run_cmd
from charms.opensearch.v0.helper_databag import Scope
from charms.opensearch.v0.helper_security import generate_password
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchError,
)
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

    def _on_tls_relation_joined(self, _: RelationJoinedEvent) -> None:
        """Request certificate when TLS relation joined."""
        self.charm.on_tls_relation_joined()

        # delete previous stored key stores if any
        self._delete_tls_resources()

        # create passwords for both unit-http/transport key_stores
        self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.UNIT_TRANSPORT.val)
        self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.UNIT_HTTP.val)

        if self.charm.unit.is_leader():
            # create passwords for both ca trust_store/admin key_store
            self._create_keystore_pwd_if_not_exists(Scope.APP, "ca")
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN.val)

            admin_cert = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN)
            if admin_cert is None:
                self._request_certificate(Scope.APP, CertType.APP_ADMIN)

        self._request_certificate(Scope.UNIT, CertType.UNIT_TRANSPORT)
        self._request_certificate(Scope.UNIT, CertType.UNIT_HTTP)

    def _on_tls_relation_changed(self, event: RelationChangedEvent) -> None:
        self.charm.on_tls_relation_broken()

        # todo: how to only call in subsequent calls -- ONLY ON CONFIG CHANGES? Check operator code
        #  perhaps test on existence of "certificates" in the tls operator peer rel data ?

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
                logger.debug(f"\n\n -- {self.charm.unit_name} -- revoked: true\n\n")
                return

        # self.charm.on_tls_relation_joined()

        if self.charm.unit.is_leader():
            self._request_certificate(Scope.APP, CertType.APP_ADMIN)

        self._request_certificate(Scope.UNIT, CertType.UNIT_TRANSPORT)
        self._request_certificate(Scope.UNIT, CertType.UNIT_HTTP)

    def _on_tls_relation_broken(self, _: RelationBrokenEvent) -> None:
        """Notify the charm that the relation is broken."""
        self.charm.on_tls_relation_broken()

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

        # check if this is a new "ca", if it is - store it in the trust store

        if secrets.get("ca", None) != event.ca:
            self.store_new_ca(event.ca)
            # todo add "need to start"

        # store the certificates and keys in a key store
        self.store_new_tls_resources(
            scope, cert_type, private_key=secrets.get("key"), cert_chain=event.chain
        )

        # seems like the admin certificate is also broadcast to non leader units on refresh request
        # so test network cut
        # if not self.charm.unit.is_leader() and scope == Scope.APP:
        #     return

        old_cert_chain = secrets.get("cert-chain", None)
        renewal = old_cert_chain is not None and old_cert_chain != event.chain

        self.charm.secrets.put_object(
            scope,
            cert_type.val,
            {
                "cert-chain": event.chain,
                "ca": event.ca,
            },
            merge=True,
        )

        for relation in self.charm.opensearch_provider.relations:
            self.charm.opensearch_provider.update_certs(relation.id, event.chain)

        if not self.charm.unit.is_leader():
            if self.all_certificates_available() and self.all_tls_resources_stored(
                only_unit_resources=True
            ):
                # store the admin certificates in non-leader units
                admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
                self.store_new_tls_resources(
                    Scope.APP,
                    CertType.APP_ADMIN,
                    admin_secrets.get("key"),
                    admin_secrets.get("cert-chain"),
                )
            else:
                # admin certificate not ready yet
                event.defer()
                return

        try:
            self.charm.on_tls_conf_set(event, scope, cert_type, renewal)
        except OpenSearchError as e:
            logger.error(e)
            event.defer()

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """Request the new certificate when old certificate is expiring."""
        try:
            scope, cert_type, secrets = self._find_secret(event.certificate, "cert")
            logger.debug(f"{scope.val}.{cert_type.val} TLS certificate expiring.")
        except TypeError:
            logger.debug("Unknown certificate expiring.")
            return

        self._request_certificate_renewal(scope, cert_type, secrets)

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

    def _get_sans(self, cert_type: CertType) -> Dict[str, List[str]]:
        """Create a list of OID/IP/DNS names for an OpenSearch unit.

        Returns:
            A list representing the hostnames of the OpenSearch unit.
            or None if admin cert_type, because that cert is not tied to a specific host.
        """
        sans = {"sans_oid": ["1.2.3.4.5.5"]}  # required for node discovery
        if cert_type == CertType.APP_ADMIN:
            return sans

        sans["sans_ip"] = [self.charm.unit_ip]
        sans["sans_dns"] = [self.charm.unit_name, socket.getfqdn()]

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
        logger.debug(
            f"\n----\n{self.charm.unit_name}: \nApp stored: {app_secrets.get('cert')}\n"
            f"Received: {event_data}\n\n----\n"
        )
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

    def all_certificates_available(self) -> bool:
        """Method that checks if all certificates are available in secrets store."""
        secrets = self.charm.secrets

        admin_secrets = secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        if (
            not admin_secrets
            or not admin_secrets.get("cert-chain")
            or not admin_secrets.get("chain")
        ):
            return False

        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            unit_secrets = secrets.get_object(Scope.UNIT, cert_type.val)
            if not unit_secrets or not unit_secrets.get("cert-chain"):
                return False

        return True

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
                f"""{keytool} -changealias
                -alias {alias}
                -destalias old-{alias}
                -keystore {store_path}
                -storepass {store_pwd}
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

        with tempfile.NamedTemporaryFile() as ca_tmp_file:
            ca_tmp_file.write(ca_cert)
            ca_tmp_file.flush()

            run_cmd(
                f"""{keytool} -importcert
                -trustcacerts
                -noprompt
                -alias {alias}
                -keystore {store_path}
                -file {alias}.cert
                -storepass {store_pwd}
                -storetype PKCS12
            """
            )

        # todo chown / chmod
        run_cmd(f"sudo chown snap_daemon:root {store_path}")

    def remove_old_ca(self, store_pass: str):
        """Remove old CA cert from trust store."""
        self._remove_key_store_content_by_alias(store_pass, alias="old-ca", key_store_name="ca")

    def store_new_tls_resources(
        self, scope: Scope, cert_type: CertType, private_key: str, cert_chain: List[str]
    ):
        """Add key and cert to keystore."""
        store_pwd = self.charm.secrets.get(scope, f"keystore-password-{cert_type.val}")

        # we store the pem format to make it easier for the python requests lib
        if cert_type == CertType.APP_ADMIN:
            with open(f"{self.certs_path}/admin-cert-chain.pem", "w+") as f:
                f.write("\n".join(cert_chain))

        self._remove_key_store_content_by_alias(store_pwd, alias=cert_type.val)

        with (
            tempfile.NamedTemporaryFile(mode="w+t") as tmp_key,
            tempfile.NamedTemporaryFile(mode="w+t") as tmp_cert,
        ):
            tmp_key.write(private_key)
            tmp_key.flush()

            tmp_cert.write("\n".join(cert_chain))
            tmp_cert.flush()

            run_cmd(
                f"""openssl pkcs12 -export
                -in {tmp_cert.name}
                -inkey {tmp_key.name}
                -out {self.certs_path}/{cert_type.val}.p12
                -name {cert_type.val}
                -password pass:{store_pwd}
            """
            )
            # todo chown / chmod

    def _remove_key_store_content_by_alias(
        self, store_pass: str, alias: str, key_store_name: Optional[str] = None
    ):
        """Remove the resources matching an alias in a keystore."""
        if not key_store_name:
            key_store_name = alias

        keytool = f"sudo {self.jdk_path}/bin/keytool"
        try:
            run_cmd(
                f"""{keytool} -delete
                -alias {alias}
                -storepass {store_pass}
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

    def _delete_tls_resources(self):
        """Delete all TLS resources in the current unit."""
        key_stores = glob.glob(f"{self.certs_path}/*")
        for key_store in key_stores:
            os.remove(key_store)
            return
