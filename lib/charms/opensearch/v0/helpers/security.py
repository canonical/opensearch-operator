# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for security related operations, such as password generation etc."""
import math
import secrets
import string
from datetime import datetime
from typing import Tuple

import bcrypt
from cryptography import x509


def generate_password() -> str:
    """Generate a random password string.

    Returns:
       A random password string.
    """
    choices = string.ascii_letters + string.digits
    return "".join([secrets.choice(choices) for _ in range(32)])


def generate_hashed_password() -> Tuple[str, str]:
    """Generates a password and its bcrypt hash.

    Returns:
        A hash and the original password
    """
    pwd = generate_password()

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd.encode("utf-8"), salt)

    return hashed.decode("utf-8"), pwd


def cert_expiration_remaining_hours(cert: string) -> int:
    """Returns the remaining hours for the cert to expire."""
    certificate_object = x509.load_pem_x509_certificate(data=cert.encode())
    time_difference = certificate_object.not_valid_after - datetime.utcnow()

    return math.floor(time_difference.total_seconds() / 3600)
