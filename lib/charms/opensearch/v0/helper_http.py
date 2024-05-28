# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""File containing http related helpers."""
from typing import Any, Dict, Optional

from tenacity import RetryCallState

# The unique Charmhub library identifier, never change it
LIBID = "f8bb15ca9ffc4e3f8d113421e03abe06"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


def error_http_retry_log(
    logger, retry_max: int, method: str, url: str, payload: Optional[Dict[str, Any]]
):
    """Return a custom log function to run before a new Tenacity retry."""

    def log_error(retry_state: RetryCallState):
        logger.error(
            f"Request {method} to {url} with payload: {payload} failed."
            f"(Attempts left: {retry_max - retry_state.attempt_number})\n"
            f"\tError: {retry_state.outcome.exception()}"
        )

    return log_error
