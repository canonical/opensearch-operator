# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this file we declare the constants and enums used by Juju secrets in Opensearch."""
from charms.opensearch.v0.helper_enums import BaseStrEnum

# The unique Charmhub library identifier, never change it
LIBID = "2f539a53ab0a4916957beaf1d6b27124"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class SecretData(BaseStrEnum):
    """Secret Data Store internals."""

    LABEL_SEPARATOR = ":"
    CACHED_META = "meta"
    CACHED_CONTENT = "content"


class OpensearchSecretConst(BaseStrEnum):
    """Opensearch Secrets related constants/labels."""

    ADMIN_PW = "admin-password"
    ADMIN_PW_HASH = f"{ADMIN_PW}-hash"
