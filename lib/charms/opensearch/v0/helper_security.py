# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for security related operations, such as password generation etc."""
import hashlib
import logging
import math
import os
import secrets
import string
import subprocess
import tempfile
from datetime import datetime
from os.path import exists
from typing import Any, Optional, Tuple

import bcrypt
from charms.opensearch.v0.helper_charm import run_cmd
from charms.opensearch.v0.opensearch_exceptions import OpenSearchCmdError
from cryptography import x509
from ops.model import Secret, SecretInfo

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
    alias_base: str,
    store_pwd: str,
    store_path: str,
    ca: str,
    keep_previous: bool,
    pre_chmod_existing: str | None = None,
    owner: str | None = None,
    final_mode: str | None = None,
    add_read_perm: bool = False,
    tolerate_import_if_listed: bool = False,
) -> bool:
    """Common implementation to store a CA chain into a PKCS12 keystore."""
    tmpdir = os.path.dirname(store_path)
    # import root first, then intermediates
    certs = list(reversed(split_ca_chain(ca)))
    if pre_chmod_existing and os.path.exists(store_path):
        try:
            run_cmd(f"sudo chmod {pre_chmod_existing} {store_path}")
        except OpenSearchCmdError:
            pass

    for i, pem in enumerate(certs):
        ix_alias = f"{alias_base}-{i}"
        old_alias = f"old-{alias_base}-{i}"

        # rename existing alias to old-<alias>-<i> if requested
        if keep_previous:
            try:
                run_cmd(
                    f"{KEYTOOL} -changealias "
                    f"-alias {ix_alias} -destalias {old_alias} "
                    f"-keystore {store_path} -storetype PKCS12",
                    f"-storepass {store_pwd}",
                )
            except OpenSearchCmdError as e:
                msg = (e.out or "") + (e.err or "")
                if ("does not exist" not in msg) and ("Keystore file does not exist" not in msg):
                    return False

        # import the cert
        fd, tmpfile = tempfile.mkstemp(dir=tmpdir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as f:
                f.write(pem)

            try:
                run_cmd(
                    f"{KEYTOOL} -importcert -noprompt "
                    f"-alias {ix_alias} -keystore {store_path} -file {tmpfile} -storetype PKCS12",
                    f"-storepass {store_pwd}",
                )
            except OpenSearchCmdError:
                if tolerate_import_if_listed:
                    listed = list_cas(store_pwd=store_pwd, store_path=store_path) or {}
                    if ix_alias in listed:
                        pass
                    else:
                        return False
                else:
                    return False
        finally:
            try:
                os.remove(tmpfile)
            except FileNotFoundError:
                pass

    # post-actions
    try:
        if owner:
            run_cmd(f"sudo chown {owner} {store_path}")
        if final_mode:
            run_cmd(f"sudo chmod {final_mode} {store_path}")
        if add_read_perm:
            run_cmd(f"sudo chmod +r {store_path}")
    except OpenSearchCmdError:
        pass

    return True


def store_s3_ca(
    alias: str, store_pwd: str, store_path: str, ca: str, keep_previous: bool = True
) -> bool:
    """Add new CA cert(s) to the PKCS12 trust store for S3."""
    logger.info("Storing CA cert(s) with alias: %s into truststore.", alias)
    return _store_ca_chain(
        alias_base=alias,
        store_pwd=store_pwd,
        store_path=store_path,
        ca=ca,
        keep_previous=keep_previous,
        pre_chmod_existing="0664",
        owner="snap_daemon:root",
        final_mode="0640",
        add_read_perm=False,
        tolerate_import_if_listed=True,  # keep your graceful fallback
    )


def store_ca(
    alias: str, store_pwd: str, store_path: str, ca: str, keep_previous: bool = True
) -> bool:
    """Add new CA cert(s) to a PKCS12 trust store (generic)."""
    logger.info("Storing CA cert(s) with alias: %s into truststore.", alias)
    return _store_ca_chain(
        alias_base=alias,
        store_pwd=store_pwd,
        store_path=store_path,
        ca=ca,
        keep_previous=keep_previous,
        pre_chmod_existing=None,
        owner=None,
        final_mode=None,
        add_read_perm=True,
        tolerate_import_if_listed=False,
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

    # split by -----END CERTIFICATE-----
    cert_blocks = split_ca_chain(stored_certs)

    start_cert_marker = "-----BEGIN CERTIFICATE-----"
    chains: dict[str, list[tuple[int, str]]] = {}

    for block in cert_blocks:
        # find the friendlyName: line produced by openssl pkcs12
        alias_line = next(
            (line for line in block.split("\n") if line.strip().startswith("friendlyName:")), None
        )
        if not alias_line:
            continue
        alias = alias_line.split("friendlyName:", 1)[-1].strip()

        # extract the PEM body
        if start_cert_marker not in block:
            continue
        pem = f"{start_cert_marker}{block.split(start_cert_marker, 1)[1]}".strip()

        # parse optional trailing -<int> index
        base = alias
        idx = 0
        parts = alias.rsplit("-", 1)
        if len(parts) == 2:
            maybe_idx = parts[1]
            try:
                idx = int(maybe_idx)
                base = parts[0]
            except ValueError:
                # alias had a dash but no numeric index, keep whole alias as base and idx=0
                pass

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
    """Remove old CA cert from trust store."""
    if not exists(store_path):
        logger.debug("Trust store %s does not exist, nothing to remove.", store_path)
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
    """Return True if keytool says that given alias does not exist."""
    msg = (exc.out or "") + (exc.err or "")
    return f"Alias <{alias}> does not exist" in msg


def _collect_aliases_to_remove(alias_base: str, store_pwd: str, store_path: str) -> list[str]:
    """List aliases that should be removed (base, base-*, old-base-*)."""
    list_cmd = f"{KEYTOOL} -list -v -keystore {store_path} -storetype PKCS12"
    list_args = f"-storepass {store_pwd}"
    try:
        result = run_cmd(list_cmd, list_args)
    except OpenSearchCmdError as e:
        logger.debug(
            "Failed to list aliases from %s: %s%s",
            store_path,
            e.out or "",
            e.err or "",
        )
        raise

    aliases_to_remove: list[str] = []
    for line in result.out.splitlines():
        if "Alias name:" not in line:
            continue
        name = line.split("Alias name:", 1)[1].strip()
        if (
            name == alias_base
            or name.startswith(f"{alias_base}-")
            or name.startswith(f"{OLD_CA_PREFIX}{alias_base}-")
        ):
            aliases_to_remove.append(name)

    return aliases_to_remove


def _remove_ca_aliases(alias_base: str, store_pwd: str, store_path: str) -> None:
    """Core logic to delete aliases for a given base name."""
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
    """Remove S3 CA cert(s) from the truststore."""
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


def _normalize_chain(text: Optional[str]) -> str:
    """Normalize a PEM chain string before hashing.

    Args:
        text (Optional[str]): PEM chain string to be normalized.

    Returns:
        str: Normalized PEM chain string.
    """
    if not text:
        return ""
    return "\n".join(line.strip() for line in text.strip().splitlines() if line.strip())


def _hash(text: str) -> str:
    """Hash a PEM chain string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _jsonify_secrets(obj: Any) -> Any:
    """Return JSON-serializable copy where Secret/SecretInfo become their string ids."""
    if isinstance(obj, (Secret, SecretInfo)):
        return obj.id
    if isinstance(obj, dict):
        return {k: _jsonify_secrets(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        t = type(obj)
        return t(_jsonify_secrets(v) for v in obj)
    return obj
