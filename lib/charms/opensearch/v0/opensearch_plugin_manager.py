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

from charms.opensearch.v0.constants_secrets import NOTIFICATIONS_LABEL
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


class SmtpEvents(Object):
    """Events handler for smtp events"""

    relation_name = SMTP_RELATION
    secret_label = NOTIFICATIONS_LABEL

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "plugin:notifications")
        self.charm = charm
        self.smtp = SmtpRequires(self.charm, self.relation_name)

        self.framework.observe(self.smtp.on.smtp_data_available, self._on_smtp_credentials_changed)
        self.framework.observe(self.charm.on.smtp_relation_broken, self._on_smtp_credentials_gone)
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    def _on_smtp_credentials_changed(self, event):
        """Creates secret containing key, value pairs for keystore"""
        if not self.charm.opensearch.is_started():
            # node must be reachable to reload settings after adding keys
            event.defer()
            return

        # return if no relation data
        if not (parameters := self.smtp.get_relation_data()):
            logger.debug("Missing relation %s", self.relation_name)
            return

        # validate data
        required_params = ["user", "password"]
        if missing_parameters := [p for p in required_params if not getattr(parameters, p)]:
            logger.error("Parameters missing from smtp-intgrator: %s" % missing_parameters)
            return

        # create keys for keystore
        user = parameters.user
        entries = {
            f"opensearch.notifications.core.email.{user}.username": f"{user}",
            f"opensearch.notifications.core.email.{user}.password": f"{parameters.password}",
        }

        self.charm.plugin_manager.add_to_keystore(entries)
        self.charm.secrets.put(Scope.UNIT, self.secret_label, json.dumps(list(entries.keys())))

        if not self.charm.unit.is_leader() or not self.charm.opensearch_peer_cm.is_provider(
            typ="main"
        ):
            return

        # if unit is main orchestrator leader, transfer keys to subclusters
        self.charm.secrets.put(Scope.APP, self.secret_label, json.dumps(entries))
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

        self.charm.plugin_manager.remove_from_keystore(keys)
        self.charm.secrets.delete(Scope.UNIT, self.secret_label)

        if not self.charm.unit.is_leader() or not self.charm.opensearch_peer_cm.is_provider(
            typ="main"
        ):
            return

        try:
            self.charm.secrets.delete(Scope.APP, self.secret_label)
            self.charm.state.app.remove_plugin_secret(self.secret_label)

            if self.charm.opensearch_peer_cm.is_provider(typ="main"):
                self.charm.peer_cluster_provider.refresh_relation_data(event)
        except SecretNotFoundError:
            logger.debug("Can't find secret %s", self.secret_label)

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


class OpenSearchPluginEvents(Object):
    """Events handler for OpenSearch plugin events"""

    def __init__(self, charm: "OpenSearchBaseCharm"):
        super().__init__(charm, "plugins")
        self.smtp_events = SmtpEvents(charm)


class OpenSearchPluginManager:
    """Manager to persist OpenSearch plugin configuration information"""

    def __init__(self, opensearch):
        self._opensearch = opensearch
        self._keystore = OpenSearchKeystore(self._opensearch)

    def add_to_keystore(self, entries):
        """Adds given entries to OpenSearch keystore"""
        for k, v in entries.items():
            self._keystore.add(k, v)
        self._keystore.reload()

    def remove_from_keystore(self, keys):
        """Deletes given keys from OpenSearch keystore"""
        for k in keys:
            self._keystore.delete(k)
        self._keystore.reload()

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
