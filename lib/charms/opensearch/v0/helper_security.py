# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for security related operations, such as password generation etc."""
import logging
import math
import os
import secrets
import string
import subprocess
import tempfile
from datetime import datetime
from os.path import exists
from typing import Optional, Tuple

import bcrypt
from charms.opensearch.v0.helper_charm import run_cmd
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from cryptography import x509

# The unique Charmhub library identifier, never change it
LIBID = "224ce9884b0d47b997357fec522f11c7"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

logger = logging.getLogger(__name__)


KEYTOOL = "opensearch.keytool"
OLD_CA_PREFIX = "old-"


def hash_string(string: str) -> str:
    """Hashes the given string."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(string.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def generate_password() -> str:
    """Generate a random password string.

    Returns:
       A random password string.
    """
    choices = string.ascii_letters + string.digits
    return "".join([secrets.choice(choices) for _ in range(32)])


def generate_hashed_password(pwd: Optional[str] = None) -> Tuple[str, str]:
    """Generates a password and its bcrypt hash.

    Returns:
        A hash and the original password
    """
    pwd = pwd or generate_password()
    return hash_string(pwd), pwd


def cert_expiration_remaining_hours(cert: string) -> int:
    """Returns the remaining hours for the cert to expire."""
    certificate_object = x509.load_pem_x509_certificate(data=cert.encode())
    time_difference = certificate_object.not_valid_after - datetime.utcnow()

    return math.floor(time_difference.total_seconds() / 3600)


def normalized_tls_subject(subject: string) -> str:
    """Removes any / character from a subject."""
    if subject.startswith("/"):
        subject = subject[1:]
    return subject.replace("/", ",")


def rfc2253_tls_subject(subject: string) -> str:
    """Format the subject as per RFC2253 (inverted and , instead of /)."""
    if subject.startswith("/"):
        inverted_arr = subject[1:].split("/")[::-1]
        return ",".join(inverted_arr)

    # only the ip address was set
    return f"CN={subject}"


def to_pkcs8(private_key: str, password: Optional[str] = None) -> str:
    """Convert a PEM key to PKCS8."""
    command = """openssl pkcs8 \
        -inform PEM \
        -outform PEM \
        -in {tmp_key_filename} \
        -topk8 \
        -v1 PBE-SHA1-3DES \
        -passout pass:"{password}" \
        -passin pass:"{password}" \
        -out {tmp_pkcs8_key_filename}"""
    if password is None:
        password = ""
        command = f"{command} -nocrypt"

    tmp_key = tempfile.NamedTemporaryFile(delete=False)
    tmp_pkcs8_key = tempfile.NamedTemporaryFile(delete=False)

    try:
        with open(tmp_key.name, "w") as f:
            f.write(private_key)

        subprocess.run(
            command.format(
                password=password,
                tmp_key_filename=tmp_key.name,
                tmp_pkcs8_key_filename=tmp_pkcs8_key.name,
            ),
            shell=True,
            text=True,
            check=True,
            encoding="utf-8",
            env=os.environ,
        )

        with open(tmp_pkcs8_key.name, "r") as f:
            return f.read()
    finally:
        os.unlink(tmp_key.name)
        os.unlink(tmp_pkcs8_key.name)


def split_ca_chain(pem_content: str) -> list[str]:
    """Split PEM chain into individual certificates."""
    end_cert_marker = "-----END CERTIFICATE-----"
    parts = [part.strip() for part in pem_content.split(end_cert_marker) if part.strip()]
    return [f"{part}\n{end_cert_marker}" for part in parts]


def store_ca(
    alias: str, store_pwd: str, store_path: str, ca: str, keep_previous: bool = True
) -> bool:
    """Add new CA cert to trust store."""
    # This loop and split are to handle when the CA is a chain with intermediate certs
    certs = list(reversed(split_ca_chain(ca)))

    for index in range(len(certs)):
        if keep_previous:
            cmd = f"{KEYTOOL} -changealias -alias {alias}-{index} -destalias {OLD_CA_PREFIX}{alias}-{index} -keystore {store_path} -storetype PKCS12"
            args = f"-storepass {store_pwd}"
            try:
                run_cmd(cmd, args)
                logger.info(
                    f"Current CA {alias}-{index} was renamed to {OLD_CA_PREFIX}{alias}-{index}."
                )
            except OpenSearchCmdError as e:
                # This message means there was no "ca" alias or store before, if it happens ignore
                if not (
                    e.out is not None
                    and (
                        f"Alias <{alias}-{index}> does not exist" in e.out
                        or "Keystore file does not exist" in e.out
                    )
                ):
                    raise

        with tempfile.NamedTemporaryFile(
            mode="w+t", dir=os.path.dirname(store_path)
        ) as ca_tmp_file:
            ca_tmp_file.write(certs[index])
            ca_tmp_file.flush()
            try:
                run_cmd(
                    f"""{KEYTOOL} -importcert \
                    -noprompt \
                    -alias {alias}-{index} \
                    -keystore {store_path} \
                    -file {ca_tmp_file.name} \
                    -storetype PKCS12
                    """,
                    f"-storepass {store_pwd}",
                )
                run_cmd(f"sudo chmod +r {store_path}")
                logger.info("New CA was added to truststore.")
            except OpenSearchCmdError as e:
                logger.error("Error storing the ca-cert: %s", e)
                return False

    return True


def list_aliases(store_pwd: str, store_path: str) -> Optional[list[str]]:
    """Fetch the aliases stored in a store."""
    if not exists(store_path):
        return None

    # we fetch the list of stored aliases
    cmd = f"{KEYTOOL} -v -list -keystore {store_path} -storetype PKCS12"
    args = f"-storepass {store_pwd}"

    try:
        resp = run_cmd(cmd, args).out.split("\n")
        return [
            line.split("Alias name:")[-1].strip()
            for line in resp
            if line.startswith("Alias name:")
        ]
    except OpenSearchCmdError as e:
        logger.error("Error reading the current truststore: %s", e)
        return None


def list_cas(store_pwd: str, store_path: str) -> Optional[dict[str, str]]:
    """List the CAs currently stored in a trust store."""
    if not exists(store_path):
        return None

    cmd = f"openssl pkcs12 -in {store_path}"
    args = f"-passin pass:{store_pwd}"
    try:
        stored_certs = run_cmd(cmd, args).out
    except OpenSearchCmdError as e:
        logging.error("Error reading the current truststore: %s", e)
        return None

    # parse output to retrieve the current CA (in case there are many)
    certificates = split_ca_chain(stored_certs)

    start_cert_marker = "-----BEGIN CERTIFICATE-----"

    certs = {}
    for cert in certificates:
        alias = [line for line in cert.split("\n") if line.strip().startswith("friendlyName:")][0]
        alias = alias.split("friendlyName:")[-1].strip()

        alias_split = alias.split("-")  # support for CA chains with multiple intermediate CAs
        ca_index = int(alias_split[-1])
        ca_alias = "-".join(alias_split[:-1])
        certs.setdefault(ca_alias, []).insert(
            ca_index, f"{start_cert_marker}{cert.split(start_cert_marker)[1]}"
        )

    # since we add a suffix for the index of the CA chain content, we need to re-arrange the output
    cas = {}
    for alias, certs_list in certs.items():
        cas[alias] = "\n".join(certs_list)

    return cas


def read_ca(alias: str, store_pwd: str, store_path: str) -> Optional[str]:
    """Load stored CA cert."""
    return (list_cas(store_pwd, store_path) or {}).get(alias)


def remove_ca(alias: str, store_pwd: str, store_path: str) -> None:
    """Remove old CA cert from trust store."""
    if not exists(store_path):
        return

    list_cmd = f"{KEYTOOL} -list -keystore {store_path} -alias {alias} -storetype PKCS12"
    list_args = f"-storepass {store_pwd}"
    try:
        run_cmd(list_cmd, list_args)
    except OpenSearchCmdError as e:
        # This message means there was no "ca" alias or store before, if it happens ignore
        if e.out and f"Alias <{alias}> does not exist" in e.out:
            return

    del_cmd = f"{KEYTOOL} -delete -keystore {store_path} -alias {alias} -storetype PKCS12"
    del_args = f"-storepass {store_pwd}"
    run_cmd(del_cmd, del_args)
    logger.info("Removed %s from truststore.", alias)


def store_key_pair(
    name: str, store_pwd: str, store_path: str, cert: str, key: str, key_pwd: str | None
) -> None:
    """Store cert in keystore."""
    try:
        os.remove(store_path)
    except OSError:
        pass

    tmp_key = tempfile.NamedTemporaryFile(
        mode="w+t", suffix=".pem", dir=os.path.dirname(store_path)
    )
    tmp_key.write(key)
    tmp_key.flush()
    tmp_key.seek(0)

    tmp_cert = tempfile.NamedTemporaryFile(
        mode="w+t", suffix=".cert", dir=os.path.dirname(store_path)
    )
    tmp_cert.write(cert)
    tmp_cert.flush()
    tmp_cert.seek(0)

    cmd = f"openssl pkcs12 -export -in {tmp_cert.name} -inkey {tmp_key.name} -out {store_path} -name {name}"
    args = f"-passout pass:{store_pwd}"
    if key_pwd:
        args = f"{args} -passin pass:{key_pwd}"

    try:
        run_cmd(cmd, args)
        run_cmd(f"sudo chmod +r {store_path}")
    except OpenSearchCmdError as e:
        logger.error("Error storing the TLS certificates for %s: %s", name, e)
    finally:
        tmp_key.close()
        tmp_cert.close()
        logger.info("TLS certificate for %s stored.", name)


def get_cert_issuer(cert: str) -> Optional[str]:
    """Retrieve the certificate issuer from a string certificate."""
    # to make sure the content is processed correctly by openssl, temporary store it in a file
    tmp_ca_file = tempfile.NamedTemporaryFile(mode="w+t", dir="/tmp")
    tmp_ca_file.write(cert)
    tmp_ca_file.flush()
    tmp_ca_file.seek(0)

    try:
        return run_cmd(f"openssl x509 -in {tmp_ca_file.name} -noout -issuer").out
    except OpenSearchCmdError as e:
        logger.error("Error reading the current truststore: %s", e)
        return None
    finally:
        tmp_ca_file.close()


def get_cert_issuer_from_path(store_pwd: str, store_path: str) -> Optional[str]:
    """Retrieve the certificate issuer from a string certificate."""
    try:
        return run_cmd(
            f"openssl pkcs12 -in {store_path}",
            f"""-nodes \
            -passin pass:{store_pwd} \
            | openssl x509 -noout -issuer
            """,
        ).out
    except OpenSearchCmdError as e:
        logger.error("Error reading the current certificate: %s", e)
        return None


def get_cert_issuer_from_keystore(store_pwd: str, store_path: str) -> Optional[str]:
    """Fetch the certificate issuer of a PKCS12 certificate."""
    if not exists(store_path):
        return None

    cmd = f"openssl pkcs12 -in {store_path} -nodes"
    args = f"-passin pass:{store_pwd} | openssl x509 -noout -issuer"
    try:
        return run_cmd(command=cmd, args=args).out
    except OpenSearchCmdError as e:
        logger.error("Error reading the current certificate: %s", e)
        return None
    except AttributeError as e:
        logger.error("Error reading secret: %s", e)
        return None
