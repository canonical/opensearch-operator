# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this file we declare the constants and enums used by Juju secrets in Opensearch."""

# The unique Charmhub library identifier, never change it
LIBID = "2f539a53ab0a4916957beaf1d6b27124"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


PW_POSTFIX = "password"
HASH_POSTFIX = f"{PW_POSTFIX}-hash"
ADMIN_PW = f"admin-{PW_POSTFIX}"
ADMIN_PW_HASH = f"{ADMIN_PW}-hash"
S3_CREDENTIALS = "s3-creds"
S3_PEER_SECRET_KEYS = [
    "secret-key",
    "access-key",
    "s3-secret-key",
    "s3-access-key",
    S3_CREDENTIALS,
]
AZURE_CREDENTIALS = "azure-creds"
AZURE_PEER_SECRET_KEYS = [
    "azure-storage-account",
    "azure-secret-key",
    "secret-key",
    "storage-account",
    AZURE_CREDENTIALS,
]
