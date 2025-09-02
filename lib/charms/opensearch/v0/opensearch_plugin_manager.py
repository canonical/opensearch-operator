# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implements the plugin manager class.

This module manages each plugin's lifecycle. It is responsible to install, configure and
upgrade of each of the plugins.

This class is instantiated at the operator level and is called at every relevant event:
config-changed, upgrade, s3-credentials-changed, etc.
"""

import json
import logging
from typing import TYPE_CHECKING

from charms.data_platform_libs.v0.object_storage import AzureStorageRequires
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.opensearch.v0.constants_charm import AZURE_RELATION, S3_RELATION
from charms.opensearch.v0.constants_secrets import (
    NOTIFICATIONS_LABEL,
    REPOSITORY_AZURE_LABEL,
    REPOSITORY_S3_LABEL,
)
from charms.opensearch.v0.models import PluginConfigType, PluginSecret
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.opensearch.v0.opensearch_keystore import (
    OpenSearchKeystore,
)
from charms.smtp_integrator.v0.smtp import DEFAULT_RELATION_NAME as SMTP_RELATION
from charms.smtp_integrator.v0.smtp import SmtpRequires
from ops.framework import Object
from ops.model import SecretNotFoundError

# The unique Charmhub library identifier, never change it
LIBID = "da838485175f47dbbbb83d76c07cab4c"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

PREFIX_NOTIFICATIONS = "opensearch.notifications.core.email"
PREFIX_S3_CLIENT = "s3.client.default"
PREFIX_AZURE_CLIENT = "azure.client.default"


class PluginEvent(Object):
    """Base event handler for plugin events"""

    def __init__(self, charm: "OpenSearchBaseCharm", plugin):
        super().__init__(charm, f"plugin:{plugin}")
        self.charm = charm

    def _validate(self, parameters) -> bool:
        """Returns false if data invalid"""
        if missing_parameters := [p for p in self.required_params if p not in parameters]:
            logger.error(
                "Parameters missing from %s: %s" % (self.relation_name, missing_parameters)
            )
            return False

        # strip values
        for key, value in parameters.items():
            if isinstance(value, str):
                parameters[key] = value.strip()
        return True

    def _on_secret_changed(self, event):
        """Handles secret changes"""
        label = self.charm.secrets.label(Scope.APP, self.secret_label)
        if event.secret.label == label:
            secret = event.secret.get_content(refresh=True)
            raw = secret.get(self.secret_label)
            keys = json.loads(raw)
            if not self.charm.plugin_manager.write_keystore(keys):
                logger.info("Could not update keystore. Deferring event.")
                event.defer()


class SmtpEvents(PluginEvent):
    """Events handler for smtp events"""

    relation_name = SMTP_RELATION
    required_params = ("user", "password")
    secret_label = NOTIFICATIONS_LABEL

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "notifications")
        self.charm = charm
        self.smtp = SmtpRequires(self.charm, self.relation_name)

        self.framework.observe(self.smtp.on.smtp_data_available, self._on_smtp_credentials_changed)
        self.framework.observe(self.charm.on.smtp_relation_broken, self._on_smtp_credentials_gone)
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _validate(self, parameters):
        """Returns missing expected parameters"""
        if missing_parameters := [p for p in self.required_params if not getattr(parameters, p)]:
            logger.error("Parameters missing from smtp-intgrator: %s" % missing_parameters)
            return False
        return True

    def _on_smtp_credentials_changed(self, event):
        """Creates secret containing key, value pairs for keystore"""
        if not self.charm.opensearch.is_node_up():
            # node must be reachable to reload settings after adding keys
            event.defer()
            return

        # return if no relation data
        if not (parameters := self.smtp.get_relation_data()):
            logger.debug("Missing relation %s", self.relation_name)
            return

        # validate data
        if not self._validate(parameters):
            return

        # create keys for keystore
        user = parameters.user
        keys = {
            f"{PREFIX_NOTIFICATIONS}.{user}.username": f"{user}",
            f"{PREFIX_NOTIFICATIONS}.{user}.password": f"{parameters.password}",
        }

        self.charm.plugin_manager.write_keystore(keys)
        self.charm.secrets.put(Scope.UNIT, self.secret_label, json.dumps(keys))

        if not self.charm.unit.is_leader():
            return

        # if unit is main orchestrator leader, transfer keys to subclusters
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.secrets.put(Scope.UNIT, self.secret_label, json.dumps(keys))
            secret_id = self.charm.secrets.get_secret_id(Scope.APP, self.secret_label)
            plugin = PluginSecret(
                relation_name=self.relation_name, secret_id=secret_id, typ=PluginConfigType.KEYS
            )
            self.charm.state.app.add_plugin_secret(self.secret_label, plugin)
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_smtp_credentials_gone(self, event):
        """Removes secret when credentials are gone"""
        secret = self.charm.secrets.get(Scope.UNIT, self.secret_label)
        keys = json.loads(secret)

        nullified = {k: None for k in keys.keys()}
        self.charm.plugin_manager.write_keystore(nullified)
        self.charm.secrets.delete(Scope.UNIT, self.secret_label)

        if not self.charm.unit.is_leader():
            return

        try:
            self.charm.secrets.delete(Scope.APP, self.secret_label)
            self.charm.state.app.remove_plugin_secret(self.secret_label)

            if self.charm.opensearch_peer_cm.is_provider(typ="main"):
                self.charm.peer_cluster_provider.refresh_relation_data(event)
        except SecretNotFoundError:
            logger.debug("Can't find secret %s", self.secret_label)


class S3Events(PluginEvent):
    """Events handler for s3-credentials events"""

    relation_name = S3_RELATION
    required_params = ("access-key", "secret-key")
    secret_label = REPOSITORY_S3_LABEL

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "repository-s3")
        self.charm = charm
        self.s3 = S3Requirer(self.charm, S3_RELATION)

        self.framework.observe(self.s3.on.credentials_changed, self._on_s3_credentials_changed)
        self.framework.observe(self.s3.on.credentials_gone, self._on_s3_credentials_gone)
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_s3_credentials_changed(self, event):
        """Creates secret containing key, value pairs for keystore"""
        if not self.charm.opensearch.is_node_up():
            # node must be reachable to reload settings after adding keys
            event.defer()
            return

        # return if no relation data
        if not (s3_parameters := self.s3.get_s3_connection_info()):
            logger.debug("Missing relation %s", self.relation_name)
            return

        # validate data
        if not self._validate(s3_parameters):
            return

        # create keys for keystore
        keys = {
            f"{PREFIX_S3_CLIENT}.access_key": s3_parameters["access-key"],
            f"{PREFIX_S3_CLIENT}.secret_key": s3_parameters["secret-key"],
        }

        self.charm.plugin_manager.write_keystore(keys)

        if not self.charm.unit.is_leader():
            return

        # if unit is main orchestrator leader, transfer keys to subclusters
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.secrets.put(Scope.APP, self.secret_label, json.dumps(keys))
            secret_id = self.charm.secrets.get_secret_id(Scope.APP, self.secret_label)
            plugin = PluginSecret(
                relation_name=self.relation_name, secret_id=secret_id, typ=PluginConfigType.KEYS
            )
            self.charm.state.app.add_plugin_secret(self.secret_label, plugin)
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_s3_credentials_gone(self, event):
        """Removes secret when credentials are gone"""
        self.charm.plugin_manager.write_keystore(
            {f"{PREFIX_S3_CLIENT}.access_key": None, f"{PREFIX_S3_CLIENT}.secret_key": None}
        )

        if not self.charm.unit.is_leader():
            return

        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            try:
                self.charm.secrets.delete(Scope.APP, self.secret_label)
                self.charm.state.app.remove_plugin_secret(self.secret_label)
                self.charm.peer_cluster_provider.refresh_relation_data(event)
            except SecretNotFoundError:
                logger.debug("Can't find secret %s", self.secret_label)


class AzureEvents(PluginEvent):
    """Events handler for azure-credentials events"""

    relation_name = AZURE_RELATION
    required_params = ("access-key", "secret-key")
    secret_label = REPOSITORY_AZURE_LABEL

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "repository-azure")
        self.charm = charm
        self.azure = AzureStorageRequires(self.charm, AZURE_RELATION)

        self.framework.observe(
            self.azure.on.storage_connection_info_changed, self._on_azure_credentials_changed
        )
        self.framework.observe(
            self.azure.on.storage_connection_info_gone, self._on_azure_credentials_gone
        )
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_azure_credentials_changed(self, event):
        """Creates secret containing key, value pairs for keystore"""
        if not self.charm.opensearch.is_node_up():
            # node must be reachable to reload settings after adding keys
            event.defer()
            return

        # return if no relation data
        if not (azure_parameters := self.azure.get_azure_storage_connection_info()):
            logger.debug("Missing relation %s", self.relation_name)
            return

        # validate data
        if not self._validate(azure_parameters):
            return

        # create keys for keystore
        keys = {
            f"{PREFIX_AZURE_CLIENT}.account": azure_parameters["storage-account"],
            f"{PREFIX_AZURE_CLIENT}.key": azure_parameters["secret-key"],
        }

        self.charm.plugin_manager.write_keystore(keys)

        if not self.charm.unit.is_leader():
            return

        # if unit is main orchestrator leader, transfer keys to subclusters
        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.secrets.put(Scope.APP, self.secret_label, json.dumps(keys))
            secret_id = self.charm.secrets.get_secret_id(Scope.APP, self.secret_label)
            plugin = PluginSecret(
                relation_name=self.relation_name, secret_id=secret_id, typ=PluginConfigType.KEYS
            )
            self.charm.state.app.add_plugin_secret(self.secret_label, plugin)
            self.charm.peer_cluster_provider.refresh_relation_data(event)

    def _on_azure_credentials_gone(self, event):
        """Removes secret when credentials are gone"""
        self.charm.plugin_manager.write_keystore(
            {f"{PREFIX_AZURE_CLIENT}.account": None, f"{PREFIX_AZURE_CLIENT}.key": None}
        )

        if not self.charm.unit.is_leader():
            return

        if self.charm.opensearch_peer_cm.is_provider(typ="main"):
            try:
                self.charm.secrets.delete(Scope.APP, self.secret_label)
                self.charm.state.app.remove_plugin_secret(self.secret_label)
                self.charm.peer_cluster_provider.refresh_relation_data(event)
            except SecretNotFoundError:
                logger.debug("Can't find secret %s", self.secret_label)


class OpenSearchPluginEvents(Object):
    """Events handler for OpenSearch plugin events"""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "plugins")
        self.smtp_events = SmtpEvents(charm)
        self.s3_events = S3Events(charm)
        self.azure = AzureEvents(charm)


class OpenSearchPluginManager:
    """Manager to persist OpenSearch plugin configuration information"""

    def __init__(self, opensearch):
        self._opensearch = opensearch
        self._keystore = OpenSearchKeystore(self._opensearch)

    def write_keystore(self, config):
        """Updates key,val pairs in OpenSearch keystore. Deletes key if val is None"""
        try:
            self._keystore.update(config)
            response = self._keystore.reload_keystore()
        except OpenSearchCmdError as e:
            logger.info("Could not update keystore %s.", e)
            return False
        except OpenSearchHttpError:
            logger.info("Could not request secure settings reload.")
            return False

        failed = response.get("_nodes", {}).get("failed", -1)
        return failed == 0
