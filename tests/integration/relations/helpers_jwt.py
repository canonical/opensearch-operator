#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
import base64
import logging
import secrets
from datetime import datetime, timedelta, timezone

import jwt

ENCODING_ALGORITHM = "HS256"


def generate_json_web_token() -> dict[str, str]:
    """Generate a JWT specific for testing in Opensearch.

    Returns: a dictionary containing the token and the signing key.
    """
    # Secret key for signing the JWT
    signing_key = secrets.token_urlsafe(32)

    # Payload data
    payload = {
        "role": "admin",
        "user": "admin",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=60),
    }

    # Encode the token and the signing-key
    encoded_jwt = jwt.encode(payload, signing_key, algorithm=ENCODING_ALGORITHM)
    signing_key_encoded = encode_str_as_base64(signing_key)

    # Test if valid JWT
    try:
        jwt.decode(encoded_jwt, signing_key, algorithms=[ENCODING_ALGORITHM])
        logging.info("JWT successfully generated")
        return {"token": encoded_jwt, "signing-key": signing_key_encoded}
    except jwt.InvalidTokenError:
        raise


def encode_str_as_base64(input_str) -> str:
    string_as_bytes = input_str.encode("ascii")
    string_as_base64 = base64.urlsafe_b64encode(string_as_bytes).decode("utf-8")
    return string_as_base64
