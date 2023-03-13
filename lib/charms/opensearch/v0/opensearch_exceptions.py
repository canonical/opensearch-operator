# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""File containing all OpenSearch related exceptions."""
import json
from typing import List, Optional

# The unique Charmhub library identifier, never change it
LIBID = "9e5bbab8a2bb475d83252500481351b2"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


class OpenSearchError(Exception):
    """Base exception class for OpenSearch errors."""


class OpenSearchMissingError(OpenSearchError):
    """Exception thrown when an action is attempted on OpenSearch when it's not installed."""


class OpenSearchInstallError(OpenSearchError):
    """Exception thrown when OpenSearch fails to be installed."""


class OpenSearchMissingSysReqError(OpenSearchError):
    """Exception thrown when OpenSearch fails to be installed."""

    def __init__(self, missing_requirements: List[str]):
        self.missing_requirements = missing_requirements


class OpenSearchStartError(OpenSearchError):
    """Exception thrown when OpenSearch fails to start."""


class OpenSearchStartTimeoutError(OpenSearchStartError):
    """Exception thrown when OpenSearch takes too long to start."""


class OpenSearchStopError(OpenSearchError):
    """Exception thrown when OpenSearch fails to stop."""


class OpenSearchStopTimeoutError(OpenSearchStopError):
    """Exception thrown when OpenSearch takes too long to stop."""


class OpenSearchRestartError(OpenSearchError):
    """Exception thrown when OpenSearch fails to restart."""


class OpenSearchNotStartedError(OpenSearchError):
    """Exception thrown when attempting an operation when the OpenSearch service is stopped."""


class OpenSearchCmdError(OpenSearchError):
    """Exception thrown when an OpenSearch bin command fails."""


class OpenSearchHttpError(OpenSearchError):
    """Exception thrown when an OpenSearch REST call fails."""

    def __init__(self, response_body: Optional[str] = None, response_code: Optional[int] = None):
        try:
            self.response_body = json.loads(response_body)
        except:
            self.response_body = None
        self.response_code = response_code


class OpenSearchHAError(OpenSearchError):
    """Exception thrown when the HA of the OpenSearch charm is violated."""


class OpenSearchScaleDownError(OpenSearchError):
    """Exception thrown when a scale-down event is not safe."""
