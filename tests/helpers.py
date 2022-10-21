# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Callable
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def patch_network_get(private_address: str = "1.1.1.1") -> Callable:
    def network_get(*args, **kwargs) -> dict:
        """Patch for the not-yet-implemented testing backend needed for `bind_address`.

        This patch decorator can be used for cases such as:
        self.model.get_binding(event.relation).network.bind_address
        """
        return {
            "bind-addresses": [
                {
                    "addresses": [{"value": private_address}],
                }
            ]
        }

    return patch("ops.testing._TestingModelBackend.network_get", network_get)


def copy_file_content_to_tmp(config_dir_path: str, source_path: str) -> str:
    """Copy the content of a file into a temporary file and return it."""
    relative_dir = ""
    if "/" in source_path:
        relative_dir = "/".join(source_path.split("/")[:-1])

    target_dir = f"{config_dir_path}/tmp/{relative_dir}"
    Path(target_dir).mkdir(parents=True, exist_ok=True)

    dest_path = f"{target_dir}/{source_path.split('/')[-1]}"
    shutil.copyfile(f"{config_dir_path}/{source_path}", dest_path)

    return dest_path


def create_utf8_encoded_private_key() -> str:
    """Creates a private key."""
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("utf-8")
    )


def create_x509_resources(expiring_in_days: int = 1) -> SimpleNamespace:
    """Generate an X509 self-signed certificate with a key and exp date."""
    # Create key if not passed
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Subject and issuer are always the same.
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Germany"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Berlin"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Canonical"),
            x509.NameAttribute(NameOID.COMMON_NAME, "canonical.com"),
        ]
    )

    now = datetime.utcnow()
    expiration = now + timedelta(days=expiring_in_days)
    cert_builder = (
        x509.CertificateBuilder(
            issuer_name=issuer,
            subject_name=subject,
            public_key=private_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=now,
            not_valid_after=expiration,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    return SimpleNamespace(
        cert=cert_builder.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        key=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8"),
        expiration=expiration,
    )
