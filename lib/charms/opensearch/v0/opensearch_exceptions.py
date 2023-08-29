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


class OpenSearchNotFullyReadyError(OpenSearchError):
    """Exception thrown when a node is started but not full ready to take on requests."""


class OpenSearchOpsLockAlreadyAcquiredError(OpenSearchError):
    """Exception thrown when a node is started but not full ready to take on requests."""


class OpenSearchCmdError(OpenSearchError):
    """Exception thrown when an OpenSearch bin command fails."""

    def __init__(self, returncode: int = None, stderr: str = None):
        super().__init__()
        self.return_code = returncode
        self.stderr = stderr

    def __str__(self):
        """Returns the string for the command error."""
        return f"Command error, code: {self.return_code}, stderr: {self.stderr}"


class OpenSearchHttpError(OpenSearchError):
    """Exception thrown when an OpenSearch REST call fails."""

    def __init__(self, response_body: Optional[str] = None, response_code: Optional[int] = None):
        try:
            self.response_body = json.loads(response_body)
        except (json.JSONDecodeError, TypeError):
            self.response_body = {}
        self.response_code = response_code


class OpenSearchHAError(OpenSearchError):
    """Exception thrown when the HA of the OpenSearch charm is violated."""


class OpenSearchScaleDownError(OpenSearchError):
    """Exception thrown when a scale-down event is not safe."""


class OpenSearchIndexError(OpenSearchError):
    """Exception thrown when an opensearch index is invalid."""


class OpenSearchSecretError(OpenSearchError):
    """Parent exception for secrets related issues within OpenSearch."""


class OpenSearchSecretInsertionError(OpenSearchSecretError):
    """Exception thrown when a secret (group) was not found."""


class OpenSearchPluginError(OpenSearchError):
    """Exception thrown when an opensearch plugin is invalid."""


class OpenSearchKeystoreError(OpenSearchError):
    """Exception thrown when an opensearch keystore is invalid."""
