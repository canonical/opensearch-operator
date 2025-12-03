# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for security related operations, such as password generation etc."""
import logging
import math
import os
import re
import secrets
import string
import subprocess
import tempfile
from datetime import datetime
from os.path import exists
from typing import Optional, Tuple

import bcrypt
import boto3
from azure.core.exceptions import AzureError
from azure.storage.blob import ContainerClient
from botocore.exceptions import BotoCoreError, ClientError
from charms.opensearch.v0.helper_charm import run_cmd
from charms.opensearch.v0.models import ObjectStorageConfig
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


def _store_ca_chain(  # noqa: C901
    *,
    alias: str,
    store_pwd: str,
    store_path: str,
    ca: str,
    keep_previous: bool,
    snap_user_with_write_permission: bool = False,
    add_read_perm: bool = False,
) -> bool:
    """Common implementation to store a CA chain into a PKCS12 keystore."""
    tmpdir = os.path.dirname(store_path)
    starter_mode = "0664"
    snap_user = "snap_daemon:root"
    final_mode = "0640"
    # import root first, then intermediates
    certs = list(reversed(split_ca_chain(ca)))
    if snap_user_with_write_permission and os.path.exists(store_path):
        try:
            run_cmd(f"sudo chmod {starter_mode} {store_path}")
        except OpenSearchCmdError:
            pass

    for i, pem in enumerate(certs):
        internal_alias = f"{alias}-{i}"
        old_internal_alias = f"old-{alias}-{i}"

        # rename existing alias to old-<alias>-<i> if requested
        if keep_previous:
            try:
                run_cmd(
                    f"{KEYTOOL} -changealias "
                    f"-alias {internal_alias} -destalias {old_internal_alias} "
                    f"-keystore {store_path} -storetype PKCS12",
                    f"-storepass {store_pwd}",
                )
            except OpenSearchCmdError as e:
                msg = (e.out or "") + (e.err or "")
                if ("does not exist" not in msg) and ("Keystore file does not exist" not in msg):
                    return False

        # import the cert
        try:
            with tempfile.NamedTemporaryFile(
                dir=tmpdir,
                mode="w",
                encoding="utf-8",
                errors="replace",
                delete=True,
            ) as tmp:
                tmp.write(pem)
                tmp.flush()
                tmp_path = tmp.name

                try:
                    run_cmd(
                        f"{KEYTOOL} -importcert -noprompt "
                        f"-alias {internal_alias} -keystore {store_path} -file {tmp_path} -storetype PKCS12",
                        f"-storepass {store_pwd}",
                    )
                except OpenSearchCmdError as e:
                    logger.error(
                        "Failed to import cert for alias %s into %s: %s",
                        internal_alias,
                        store_path,
                        (e.out or "") + (e.err or ""),
                    )
                    return False
        except OSError as e:
            # tmp file creation issues
            logger.error("Failed to create temporary file for CA import: %s", e)
            return False

    # post-actions
    try:
        command = ""
        if snap_user_with_write_permission:
            command = f"sudo chown {snap_user} {store_path}; sudo chmod {final_mode} {store_path};"
        if add_read_perm:
            command += f"sudo chmod +r {store_path}"
        run_cmd(command)
    except OpenSearchCmdError:
        pass

    return True


def store_s3_ca(
    alias: str, store_pwd: str, store_path: str, ca: str, keep_previous: bool = True
) -> bool:
    """Add new CA cert(s) to the PKCS12 trust store for S3.

    Args:
        alias: Alias to use for the CA certs.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.
        ca: CA cert(s) to store.
        keep_previous: Whether to keep the previous CA certs in the trust store.

    Returns:
        bool: True if the operation succeeded, False otherwise.
    """
    logger.info("Storing CA cert(s) with alias: %s into truststore.", alias)
    return _store_ca_chain(
        alias=alias,
        store_pwd=store_pwd,
        store_path=store_path,
        ca=ca,
        keep_previous=keep_previous,
        snap_user_with_write_permission=True,
    )


def store_ca(
    alias: str, store_pwd: str, store_path: str, ca: str, keep_previous: bool = True
) -> bool:
    """Add new CA cert(s) to a PKCS12 trust store (generic).

    Args:
        alias: Alias to use for the CA certs.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.
        ca: CA cert(s) to store.
        keep_previous: Whether to keep the previous CA certs in the trust store.

    Returns:
        bool: True if the operation succeeded, False otherwise.
    """
    logger.info("Storing CA cert(s) with alias: %s into truststore.", alias)
    return _store_ca_chain(
        alias=alias,
        store_pwd=store_pwd,
        store_path=store_path,
        ca=ca,
        keep_previous=keep_previous,
        add_read_perm=True,
    )


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


def list_cas(store_pwd: str, store_path: str) -> Optional[dict[str, str]]:  # noqa: C901
    """List the CAs currently stored in a trust store.

    Args:
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.

    Returns:
        A mapping from base alias to full concatenated PEM chain.
        If an alias is partitioned as <alias>-0, <alias>-1, ... in the store,
        they are reassembled and returned under the base <alias> key.
    """
    if not exists(store_path):
        return None

    cmd = f"openssl pkcs12 -in {store_path}"
    args = f"-passin pass:{store_pwd}"
    try:
        stored_certs = run_cmd(cmd, args, use_errors_replace=True).out
    except OpenSearchCmdError as e:
        logging.error("Error reading the current truststore: %s", e)
        return None

    # split by -----END CERTIFICATE-----
    cert_blocks = split_ca_chain(stored_certs)

    start_cert_marker = "-----BEGIN CERTIFICATE-----"
    chains: dict[str, list[tuple[int, str]]] = {}

    for block in cert_blocks:
        # find the friendlyName: line produced by openssl pkcs12
        alias_line = next(
            (line for line in block.split("\n") if line.strip().startswith("friendlyName:")), None
        )
        alias = alias_line.split("friendlyName:", 1)[-1].strip()
        pem = f"{start_cert_marker}{block.split(start_cert_marker, 1)[1]}".strip()

        # parse optional trailing -<int> index
        base = alias
        idx = 0
        parts = alias.rsplit("-", 1)
        if len(parts) == 2 and parts[1].isdigit():
            # Only treat as index if suffix is purely digits
            idx = int(parts[1])
            base = parts[0]

        chains.setdefault(base, []).append((idx, pem))

    # reassemble chains in index order
    out: dict[str, str] = {}
    for base, items in chains.items():
        items.sort(key=lambda t: t[0])
        out[base] = "\n".join(p for _, p in items if p)

    return out


def read_ca(alias: str, store_pwd: str, store_path: str) -> Optional[str]:
    """Load stored CA cert."""
    return (list_cas(store_pwd, store_path) or {}).get(alias)


def remove_ca(alias: str, store_pwd: str, store_path: str) -> None:
    """Remove old CA cert from the truststore.

    Args:
        alias: Alias to use for the CA certs.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.
    """
    if not exists(store_path):
        logger.debug("Truststore %s does not exist, nothing to remove.", store_path)
        return

    list_cmd = f"{KEYTOOL} -list -keystore {store_path} -alias {alias} -storetype PKCS12"
    list_args = f"-storepass {store_pwd}"
    try:
        run_cmd(list_cmd, list_args)
    except OpenSearchCmdError as e:
        if _is_alias_missing_error(e, alias):
            logger.debug(
                "Alias %s not found in %s when listing before delete, ignoring.",
                alias,
                store_path,
            )
            return
        # Anything else is a real error
        raise

    del_cmd = f"{KEYTOOL} -delete -keystore {store_path} -alias {alias} -storetype PKCS12"
    del_args = f"-storepass {store_pwd}"
    try:
        run_cmd(del_cmd, del_args)
    except OpenSearchCmdError as e:
        if _is_alias_missing_error(e, alias):
            logger.debug(
                "Alias %s already gone from %s when deleting, ignoring.",
                alias,
                store_path,
            )
            return
        raise

    logger.info("Removed %s from truststore.", alias)


def _is_alias_missing_error(exc: OpenSearchCmdError, alias: str) -> bool:
    """Return True if keytool says that given alias does not exist.

    Args:
        exc: The OpenSearchCmdError to check.
        alias: The alias that was attempted to be deleted.

    Returns:
        bool: True if the error message indicates that the alias does not exist.
    """
    msg = (exc.out or "") + (exc.err or "")
    return f"Alias <{alias}> does not exist" in msg


def _collect_aliases_to_remove(alias_base: str, store_pwd: str, store_path: str) -> list[str]:
    """List aliases that should be removed (base, base-*, old-base-*).

    Args:
        alias_base: The base alias to match.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.

    Returns:
        List of aliases to remove.
    """
    # Get all aliases from the keystore
    all_aliases = list_aliases(store_pwd=store_pwd, store_path=store_path)
    if all_aliases is None:
        logger.debug("Could not list aliases from %s, no aliases to remove.", store_path)
        return []

    aliases_to_remove: list[str] = []
    for name in all_aliases:
        if name.startswith(f"{alias_base}-"):
            # Verify the suffix is a digit
            suffix = name.split("-")[-1]
            if suffix.isdigit():
                aliases_to_remove.append(name)

    return aliases_to_remove


def _remove_ca_aliases(alias_base: str, store_pwd: str, store_path: str) -> None:
    """Core logic to delete aliases for a given base name.

    Args:
        alias_base: The base alias to match.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.
    """
    aliases_to_remove = _collect_aliases_to_remove(
        alias_base=alias_base, store_pwd=store_pwd, store_path=store_path
    )

    if not aliases_to_remove:
        logger.debug("No aliases matching %s/* found in %s.", alias_base, store_path)
        return
    logger.info("Aliases: %s going to be removed", ", ".join(aliases_to_remove))
    for name in aliases_to_remove:
        del_cmd = f"{KEYTOOL} -delete -keystore {store_path} " f"-alias {name} -storetype PKCS12"
        del_args = f"-storepass {store_pwd}"
        try:
            run_cmd(del_cmd, del_args)
            logger.info("Removed %s from truststore %s.", name, store_path)
        except OpenSearchCmdError as e:
            # If the alias is not found, just ignore it. It can be removed before delete.
            if _is_alias_missing_error(e, name):
                logger.debug(
                    "Alias %s already gone from %s when deleting, ignoring.",
                    name,
                    store_path,
                )
                continue
            raise


def remove_s3_ca(alias: str, store_pwd: str, store_path: str) -> None:
    """Remove S3 CA cert(s) from the truststore.

    Args:
        alias: Alias to use for the CA certs.
        store_pwd: Password for the trust store.
        store_path: Path to the trust store.
    """
    if not alias:
        logger.debug("remove_s3_ca called with empty alias, nothing to do.")
        return

    if not exists(store_path):
        logger.debug("Trust store %s does not exist, nothing to remove.", store_path)
        return

    try:
        run_cmd(f"sudo chmod 0664 {store_path}")
    except OpenSearchCmdError as e:
        logger.warning(
            "Failed to chmod 0664 on %s before S3 CA removal: %s%s",
            store_path,
            e.out or "",
            e.err or "",
        )
    _remove_ca_aliases(alias_base=alias, store_pwd=store_pwd, store_path=store_path)
    logger.info("Removed %s from truststore %s.", alias, store_path)


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
            use_errors_replace=True,
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
        return run_cmd(command=cmd, args=args, use_errors_replace=True).out
    except OpenSearchCmdError as e:
        logger.error("Error reading the current certificate: %s", e)
        return None
    except AttributeError as e:
        logger.error("Error reading secret: %s", e)
        return None


def _normalize_certificate_chain(text: Optional[str]) -> str:
    """Normalize a PEM chain string before hashing.

    Args:
        text (Optional[str]): PEM chain string to be normalized.

    Returns:
        str: Normalized PEM chain string.
    """
    if not text:
        return ""
    return "\n".join(line.strip() for line in text.strip().splitlines() if line.strip())


def normalize_certificate_chain_unordered(chain: str) -> list[str]:
    """Normalize a PEM chain into a sorted list of cert blocks for comparison.

    Args:
        chain: PEM chain string.

    Returns:
        list[str]: List of certificate blocks, sorted by normalized content.

    This makes comparison robust to:
    - whitespace differences
    - order of certificates within the chain
    """
    blocks = _split_pem_chain(chain)
    # Use existing _normalize_certificate_chain on each block to clean whitespace etc.
    normalized_blocks = [
        _normalize_certificate_chain(block) for block in blocks if block and block.strip()
    ]
    # Sort so order does not matter
    return sorted(normalized_blocks)


def _split_pem_chain(chain: str) -> list[str]:
    """Split a PEM chain into individual certificate blocks.

    Args:
        chain: PEM chain string.

    Returns:
        list[str]: List of certificate blocks.
    """
    if not chain:
        return []

    # Match complete / valid certificate blocks
    pattern = r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
    matches = re.findall(pattern, chain, flags=re.DOTALL)

    return [
        "\n".join(line.strip() for line in cert.splitlines() if line.strip()) for cert in matches
    ]


def verify_s3_credentials(cfg: ObjectStorageConfig) -> bool:
    """Validate S3 credentials + CA using boto3.

    Args:
        cfg: ObjectStorageConfigobject

    Returns:
        True if credentials (and CA) work with S3, False otherwise.

    All errors are logged with full traceback here.
    """
    s3_cfg = cfg.s3

    ca_tmp_path = None
    verify_param: str | bool = True

    # If we have a custom CA chain, write it to a temp file and pass it to boto3
    if s3_cfg.tls_ca_chain:
        fd, ca_tmp_path = tempfile.mkstemp(prefix="opensearch-s3-ca-", suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(s3_cfg.tls_ca_chain)
        verify_param = ca_tmp_path

    try:
        session = boto3.session.Session(
            aws_access_key_id=s3_cfg.credentials.access_key,
            aws_secret_access_key=s3_cfg.credentials.secret_key,
            aws_session_token=getattr(s3_cfg.credentials, "session_token", ""),
        )

        logger.info(
            "Verifying S3 with endpoint=%r bucket=%r region=%r has_ca=%r verify=%r",
            s3_cfg.endpoint,
            s3_cfg.bucket,
            s3_cfg.region,
            bool(s3_cfg.tls_ca_chain),
            verify_param,
        )

        s3_client = session.client(
            "s3",
            endpoint_url=s3_cfg.endpoint,
            region_name=s3_cfg.region,
            verify=verify_param,
        )

        # This will test both credentials and TLS/CA
        s3_client.head_bucket(Bucket=s3_cfg.bucket)

        logger.info("S3 credential validation with boto3 succeeded.")
        return True

    except (BotoCoreError, ClientError) as e:
        logger.error(
            "S3 credential validation with boto3 failed: %s",
            e,
            exc_info=e,
        )
        return False

    finally:
        if ca_tmp_path:
            try:
                os.remove(ca_tmp_path)
            except FileNotFoundError:
                pass


def verify_azure_credentials(cfg: ObjectStorageConfig) -> bool:
    """Validate Azure Storage credentials using azure-storage-blob.

    Args:
        cfg: ObjectStorageConfigobject

    Returns:
        True if we can access the configured container, False otherwise.

    Uses the storage-account, secret-key and container fields provided by
    azure-storage-integrator.
    """
    az_cfg = cfg.azure

    # TODO move this to the pydantic model validation
    if az_cfg.connection_protocol not in {"http", "https"}:
        logger.warning(
            "Azure Storage credential validation failed: unsupported connection protocol %s",
            az_cfg.connection_protocol,
        )
        return False

    try:
        account_name = az_cfg.credentials.storage_account
        account_key = az_cfg.credentials.secret_key
        container_name = az_cfg.container

        # If azure integrator ever sends a custom endpoint, we will use it.
        # Otherwise, we will use public Azure blob endpoint.
        raw_endpoint = az_cfg.endpoint
        account_url = raw_endpoint.rsplit("/", 1)[0]
        account_url = account_url or f"https://{account_name}.blob.core.windows.net"

        container_client = ContainerClient(
            account_url=account_url,
            container_name=container_name,
            credential=account_key,
        )

        # check credentials.
        container_client.get_container_properties()

        logger.info("Azure Storage credential validation succeeded.")
        return True

    except AzureError as e:
        logger.error(
            "Azure Storage credential validation failed: %s",
            e,
            exc_info=e,
        )
        return False
