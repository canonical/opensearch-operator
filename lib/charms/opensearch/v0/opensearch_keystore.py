# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the keystore logic.

This module manages OpenSearch keystore access and lifecycle.
"""
import logging
import os
import secrets
import string
from abc import ABC
from typing import Dict, List

from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_secrets import OpenSearchSecrets
from ops import SecretNotFoundError
from ops.charm import SecretChangedEvent

# The unique Charmhub library identifier, never change it
LIBID = "de98efa151804b699d5d6128fa100807"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


class OpenSearchKeystoreError(OpenSearchError):
    """Exception thrown when an opensearch keystore is invalid."""


class Keystore(ABC):
    """Abstract class that represents the keystore."""

    def __init__(self, charm):
        """Creates the keystore manager class."""
        self._charm = charm
        self._opensearch = charm.opensearch
        self._keytool = charm.opensearch.paths.jdk + "/bin/keytool"
        self._keystore = ""
        self._password = None

    @property
    def password(self) -> str:
        """Returns the password for the store."""
        return self._password

    @password.setter
    def password(self, value: str) -> None:
        """Sets the password for the store."""
        self._password = value

    def update_password(self, old_pwd: str, pwd: str) -> None:
        """Updates the password for the truststore."""
        if not pwd or not old_pwd:
            raise OpenSearchKeystoreError("Missing password for truststore")
        if not os.path.exists(self._keystore):
            raise OpenSearchKeystoreError(f"{self._keystore} not found")
        try:
            self._opensearch._run_cmd(
                self._keytool,
                f"-storepasswd -new {pwd} -keystore {self._keystore} " f"-storepass {old_pwd}",
            )
        except OpenSearchCmdError as e:
            raise OpenSearchKeystoreError(str(e))

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
        if not os.path.exists(self._keystore):
            raise OpenSearchKeystoreError(f"{self._keystore} not found")

        for key, filename in entries.items():
            # First, try removing the key, as a new file will be added:
            try:
                self.delete([key])
            except OpenSearchKeystoreError:
                # Ignore, it means only the alias does not exist yet
                pass
            try:
                # Not using OPENSEARCH_BIN path
                self._opensearch._run_cmd(
                    self._keytool,
                    f"-import -alias {key} "
                    f"-file {filename} -storetype JKS "
                    f"-storepass {self.password} "
                    f"-keystore {self._keystore} -noprompt",
                )
            except OpenSearchCmdError as e:
                raise OpenSearchKeystoreError(str(e))

    def delete(self, entries: List[str]) -> None:
        """Removes a new set of entries to the keystore."""
        if not os.path.exists(self._keystore):
            raise OpenSearchKeystoreError(f"{self._keystore} not found")

        for key in entries:
            try:
                # Not using OPENSEARCH_BIN path
                self._opensearch._run_cmd(
                    self._keytool,
                    f"-delete -alias {key} "
                    f"-keystore {self._keystore} "
                    f"-storepass {self.password} -noprompt",
                )
            except OpenSearchCmdError as e:
                if "does not exist in the keystore" not in str(e):
                    raise OpenSearchKeystoreError(str(e))
                logger.info(
                    "opensearch_keystore.delete:"
                    f" Key {key} not found in keystore, continuing..."
                )


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
    """Manages the default CA truststore and its password."""

    OS_CA_TRUSTSTORE_PWD = "opensearch-ca-truststore-pwd"
    INITIAL_PWD = "changeit"

    def __init__(self, charm):
        """Creates the keystore manager class."""
        super().__init__(charm)
        self._keystore = charm.opensearch.paths.ca_truststore

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


class OpenSearchTruststoreManager(OpenSearchSecrets):
    """Encapsulates the Truststore management.

    Manages the truststore file and Juju3 secrets for its password.
    """

    JUJU_SECRET_TRUSTSTORE_PWD_KEY = "opensearch-ca-truststore-pwd"

    def __init__(self, charm, peer_relation: str):
        super().__init__(charm, peer_relation)
        self.truststore = OpenSearchTruststore(charm)
        # This unit taken leadership, check if the secret is already set or not
        self.framework.observe(self._charm.on.leader_elected, self._on_leader_elected)
        self.framework.observe(self._charm.on.secret_changed, self._on_secret_changed)

    def _generate_random_pwd(self, length: int = 24) -> str:
        """Generates a random password."""
        choices = string.ascii_letters + string.digits
        return "".join([secrets.choice(choices) for i in range(length)])

    def _on_leader_elected(self, _):
        """Initialize the keystore password if needed."""
        self._initialize_password_if_needed()

    def _initialize_password_if_needed(
        self,
        key: str = JUJU_SECRET_TRUSTSTORE_PWD_KEY,
        scope: Scope = Scope.APP,
        initial_pwd: str = OpenSearchTruststore.INITIAL_PWD,
    ):
        """Initialize the keystore password.

        This method will create the secret if it does not exist already.
        """
        if not self._charm.unit.is_leader():
            # Nothing to do with non-leaders
            return
        if not self._get_juju_secret(scope, key):
            # Create a new secret and store it with the initial_pwd
            return self._add_juju_secret(scope, key, value={key: initial_pwd})
        if self._get_juju_secret(scope, key) == initial_pwd:
            # secret already exists and has been set the first time with the initial_pwd
            # now update it with the correct value
            return self._add_or_update_juju_secret(
                scope, key, value={key: self._generate_random_pwd()}
            )

    def _on_secret_changed(self, event: SecretChangedEvent):
        """Refresh secret and re-run corresponding actions if needed."""
        secret = event.secret
        label = self.label(Scope.APP, self.JUJU_SECRET_TRUSTSTORE_PWD_KEY)
        if secret.label != label:
            return

        try:
            old_pwd = secret.get_content()
            new_pwd = secret.peek_content()
        except SecretNotFoundError:
            return None
        # Update the  keystore password as the secret changed
        self.truststore.update_password(old_pwd, new_pwd)
        # Commit the change
        secret.get_content(refresh=True)

        # Password has changed and the truststore has been updated, we need to reload it
        # For that, update the jvm.options and restart the service
        self._charm.opensearch_config.configure_jvm_ca_truststore(self.truststore.get_jvm_config())
        self._charm.on[self.service_manager.name].acquire_lock.emit(
            callback_override="_start_opensearch"
        )

    @property
    def password(self) -> str:
        """Returns the password for the truststore.

        Given we use -storepass at opening, it updates the password automatically.
        """
        return self._get_juju_secret_content(Scope.APP, self.JUJU_SECRET_TRUSTSTORE_PWD_KEY).get(
            self.JUJU_SECRET_TRUSTSTORE_PWD_KEY, OpenSearchTruststore.INITIAL_PWD
        )

    def add(self, entries: Dict[str, str]) -> None:
        """Adds a new set of entries to the keystore.

        First, recover the password from the juju secret and pass to the TS object.
        Then, set the values.
        """
        self.truststore.password = self.password
        self.truststore.add(entries)

    def delete(self, entries: List[str]) -> None:
        """Deletes a set of entries from the keystore.

        First, recover the password from the juju secret and pass to the TS object.
        Then, delete the key/value.
        """
        self.truststore.password = self.password
        self.truststore.delete(entries)
