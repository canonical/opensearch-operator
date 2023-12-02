# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""
import logging
import os
import secrets
import string
from abc import ABC, abstractmethod
from typing import Dict, List

from charms.data_platform_libs.v0.data_secrets import APP_SCOPE
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchError,
    OpenSearchHttpError,
)

# The unique Charmhub library identifier, never change it
LIBID = "de98efa151804b699d5d6128fa100807"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


def _generate_random_pwd(length: int = 24) -> str:
    """Generates a random password."""
    choices = string.ascii_letters + string.digits
    return "".join([secrets.choice(choices) for i in range(length)])


class OpenSearchKeystoreError(OpenSearchError):
    """Exception thrown when an opensearch keystore is invalid."""


class Keystore(ABC):
    """Abstract class that represents the keystore."""

    def __init__(self, charm):
        """Creates the keystore manager class."""
        self._charm = charm
        self._opensearch = charm.opensearch
        self._keytool = charm.opensearch.paths.jdk + "/bin/keytool"

    @abstractmethod
    def add(self, entries: Dict[str, str]) -> None:
        """Adds a new set of entries to the keystore."""
        pass

    @abstractmethod
    def delete(self, entries: List[str]) -> None:
        """Removes a new set of entries to the keystore."""
        pass

    @abstractmethod
    def list(self, alias: str = None) -> None:
        """Lists all key/values in the keystore, or optionally, the specific alias."""
        pass


class OpenSearchKeystore(Keystore):
    """Manages keystore."""

    def __init__(self, charm):
        """Creates the keystore manager class."""
        super().__init__(charm)
        self._keytool = "opensearch-keystore"

    def add(self, entries: Dict[str, str]) -> None:
        """Adds a given key to the "opensearch" keystore."""
        if not entries:
            return  # no key/value to add, no need to request reload of keystore either
        for key, value in entries.items():
            self._add(key, value)
        self._reload_keystore()

    def delete(self, entries: List[str]) -> None:
        """Removes a given key from "opensearch" keystore."""
        if not entries:
            return  # no key/value to remove, no need to request reload of keystore either
        for key in entries:
            self._delete(key)
        self._reload_keystore()

    def list(self, alias: str = None) -> List[str]:
        """Lists the keys available in opensearch's keystore."""
        try:
            return self._opensearch.run_bin(self._keytool, "list").split("\n")
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    def _add(self, key: str, value: str):
        if not value:
            raise OpenSearchKeystoreError("Missing keystore value")
        try:
            # Add newline to the end of the key, if missing
            value += "" if value.endswith("\n") else "\n"
            self._opensearch.run_bin(self._keytool, f"add --force {key}", stdin=value)
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    def _delete(self, key: str) -> None:
        try:
            self._opensearch.run_bin(self._keytool, f"remove {key}")
        except OpenSearchCmdError as e:
            if "does not exist in the keystore" in str(e):
                logger.info(
                    "opensearch_keystore._delete:"
                    f" Key {key} not found in keystore, continuing..."
                )
                return
            raise OpenSearchKeystoreError(str(e))

    def _reload_keystore(self) -> None:
        """Updates the keystore value (adding or removing) and reload."""
        try:
            # Reload the security settings and return if opensearch needs restart
            response = self._opensearch.request("POST", "_nodes/reload_secure_settings")
            logger.debug(f"_update_keystore_and_reload: response received {response}")
        except OpenSearchHttpError as e:
            raise OpenSearchKeystoreError(
                f"Failed to reload keystore: error code: {e.response_code}, error body: {e.response_body}"
            )


class OpenSearchTruststore(Keystore):
    """Manages the default CA truststore."""

    OS_CA_TRUSTSTORE_PWD = "opensearch-ca-truststore-pwd"

    def __init__(self, charm):
        """Creates the keystore manager class."""
        super().__init__(charm)
        self._keystore = charm.opensearch.paths.ca_truststore
        self._juju_secret = charm.secrets

    @property
    def password(self) -> str:
        """Returns the password for the truststore.

        Given we use -storepass at opening, it updates the password automatically.
        """
        pwd = self._juju_secret.get(
            APP_SCOPE, self.OS_CA_TRUSTSTORE_PWD, default=_generate_random_pwd()
        )
        # Check now if the pwd is actually new, if yes, then either there was no key before
        # OR the password has expired and changed. In both cases, we need to update the keystore
        if pwd != self._juju_secret.get(APP_SCOPE, self.OS_CA_TRUSTSTORE_PWD):
            self._juju_secret.set(APP_SCOPE, self.OS_CA_TRUSTSTORE_PWD, pwd)
        return pwd

    def list(self, alias: str = None) -> List[str]:
        """Lists the keys available in opensearch's keystore."""
        try:
            # Not using OPENSEARCH_BIN path
            return self._opensearch._run_cmd(self._keytool, f"-v -list -keystore {self._keystore}")
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    def add(self, entries: Dict[str, str]) -> None:
        """Adds a new set of entries to the keystore."""
        if not entries:
            raise OpenSearchKeystoreError("Missing entries for keystore")
        for key, value in entries.items():
            self._add(key, value)

    def load_file(self, files: Dict[str, str]) -> None:
        """Loads a key file to the keystore.

        The input format is:
        files = {
            "value_in_keystore": "/path/to/file",
        }
        """
        for key, file in files.items():
            if not os.path.exists(file):
                raise OpenSearchKeystoreError(f"{file} not found")
            self._opensearch._add(key, file)

    def delete(self, entries: List[str]) -> None:
        """Removes a new set of entries to the keystore."""
        if not entries:
            raise OpenSearchKeystoreError("Missing entries for keystore")
        for key in entries:
            self._delete(key)

    def _add(self, key: str, capath: str):
        if not capath:
            raise OpenSearchKeystoreError("Missing keystore value")
        if not os.path.exists(self._keystore):
            raise OpenSearchKeystoreError(f"{self._keystore} not found")
        # First, try removing the key, as a new capath will be added:
        try:
            self._delete(key)
        except OpenSearchKeystoreError:
            # Ignore, it means only the alias does not exist yet
            pass

        try:
            # Not using OPENSEARCH_BIN path
            self._opensearch._run_cmd(
                self._keytool,
                f"-import -alias {key} "
                f"-file {capath} -storetype JKS "
                f"-storepass {self.password} "
                f"-keystore {self._keystore} -noprompt",
            )
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

    def _delete(self, key: str) -> None:
        if not os.path.exists(self._keystore):
            raise OpenSearchKeystoreError(f"{self._keystore} not found")
        try:
            # Not using OPENSEARCH_BIN path
            self._opensearch._run_cmd(
                self._keytool,
                f"-delete -alias {key} "
                f"-keystore {self._keystore} "
                f"-storepass {self.password} -noprompt",
            )
        except OpenSearchCmdError as e:
            if "does not exist in the keystore" in str(e):
                logger.info(
                    "opensearch_keystore._delete:"
                    f" Key {key} not found in keystore, continuing..."
                )
                return
            raise OpenSearchKeystoreError(str(e))

    def get_jvm_config(self) -> Dict[str, str]:
        """Returns a dict containing the jvm options to be added for this truststore.

        These configs should be added to jvm.options.
        """
        if not os.path.exists(self._keystore):
            raise OpenSearchKeystoreError(f"{self._keystore} not found")
        return {
            "-Djavax.net.ssl.trustStore": self._keystore,
            "-Djavax.net.ssl.trustStorePassword": self.password,
        }
