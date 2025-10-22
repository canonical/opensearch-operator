#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Application charm that connects to opensearch using the opensearch-client relation."""

import json
import logging
from typing import Dict, List, Optional, Union

import requests
from charms.data_platform_libs.v0.data_interfaces import (
    AuthenticationEvent,
    OpenSearchRequires,
)
from ops.charm import ActionEvent, CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)


CERT_PATH = "/tmp/test_cert.ca"


class ApplicationCharm(CharmBase):
    """Application charm that connects to database charms.

    Enters BlockedStatus if it cannot constantly reach the database.
    """

    def __init__(self, *args):
        super().__init__(*args)
        # Default charm events.
        self.framework.observe(self.on.update_status, self._on_update_status)

        # `albums` index is used in integration test
        self.first_opensearch = OpenSearchRequires(self, "first-index", "albums", "")

        index_name = f'{self.app.name.replace("-", "_")}_second_opensearch'
        # set invalid permissions to guarantee we still get default permissions.
        self.second_opensearch = OpenSearchRequires(self, "second-index", index_name, "hackerman")

        # Checking comma-separated permissions. These should still basically have admin
        # permissions.
        self.admin_opensearch = OpenSearchRequires(self, "admin", "admin-index", "admin,default")

        self.relations = {
            "first-index": self.first_opensearch,
            "second-index": self.second_opensearch,
            "admin": self.admin_opensearch,
        }

        for relation_handler in self.relations.values():
            self.framework.observe(
                relation_handler.on.index_created, self._on_authentication_updated
            )
            self.framework.observe(
                relation_handler.on.authentication_updated, self._on_authentication_updated
            )

        self.framework.observe(self.on.run_request_action, self._on_run_request_action)

    def _on_update_status(self, _) -> None:
        """Health check for index connection."""
        if self.connection_check():
            self.unit.status = ActiveStatus()
        else:
            logger.error("connection check to opensearch charm failed")
            self.unit.status = BlockedStatus("No connection to opensearch charm")

    def connection_check(self) -> bool:
        """Simple connection check to see if backend exists and we can connect to it."""
        relations = []
        for relation in self.relations.keys():
            relations += self.model.relations.get(relation, [])
        if not relations:
            return False

        connected = True
        for relation in relations:
            try:
                self.relation_request(relation.name, relation.id, "GET", "/")
            except Exception as e:
                logger.error(e)
                logger.error(f"relation {relation} didn't connect")
                connected = False

        return connected

    def _get_requires(self, relation_name):
        for requires in self.relations.values():
            if requires.relation_name == relation_name:
                return requires

    def _on_authentication_updated(self, event: AuthenticationEvent):
        if not hasattr(event, "relation"):
            return

        requires = self.relations.get(event.relation.name)
        tls_ca = requires.fetch_relation_field(event.relation.id, "tls-ca")

        if not tls_ca:
            event.defer()  # We're waiting until we get a CA.
            return

        logger.error(f"writing cert to {CERT_PATH}.")
        with open(CERT_PATH, "w") as f:
            f.write(tls_ca)

    # ==============
    #  Action hooks
    # ==============

    def _on_run_request_action(self, event: ActionEvent):
        logger.info(event.params)
        relation_id = event.params["relation-id"]
        method = event.params["method"]
        endpoint = event.params["endpoint"]
        payload = event.params.get("payload", None)
        if payload:
            payload = payload.replace("\\", "")

        requires = self._get_requires(event.params["relation-name"])
        username = requires.fetch_relation_field(relation_id, "username")
        password = requires.fetch_relation_field(relation_id, "password")
        hosts = requires.fetch_relation_field(relation_id, "endpoints")

        if not username or not password:
            event.fail("Secrets not accessible yet.")
            return

        host = None
        if not hosts:
            return

        host = hosts.split(",")[0]
        host_addr, port = host.split(":")

        logger.info(f"sending {method} request to {endpoint}")
        try:
            response = self.request(
                method, endpoint, int(port), username, password, host_addr, payload
            )
        except OpenSearchHttpError as e:
            response = [str(e)]
        logger.info(response)

        event.set_results({"results": json.dumps(response)})

    # =================================
    #  Opensearch connection functions
    # =================================

    def relation_request(
        self,
        relation_name: str,
        relation_id: int,
        method: str,
        endpoint: str,
        payload: Optional[Dict[str, any]] = None,
    ) -> Union[Dict[str, any], List[any]]:
        """Make an HTTP request to a specific relation."""
        requires = self._get_requires(relation_name)
        username = requires.fetch_relation_field(relation_id, "username")
        password = requires.fetch_relation_field(relation_id, "password")
        hosts = requires.fetch_relation_field(relation_id, "endpoints")

        if None in [username, password] or not hosts:
            raise OpenSearchHttpError

        host, port = hosts.split(",")[0].split(":")

        return self.request(
            method,
            endpoint,
            int(port),
            username,
            password,
            host,
            payload=payload,
        )

    def request(
        self,
        method: str,
        endpoint: str,
        port: int,
        username: str,
        password: str,
        host: str,
        payload: Optional[Dict[str, any]] = None,
    ) -> Union[Dict[str, any], List[any]]:
        """Make an HTTP request.

        TODO swap this over to a more normal opensearch client
        Args:
            method: matching the known http methods.
            endpoint: relative to the base uri.
            payload: JSON / map body payload.
            host: host of the node we wish to make a request on.
            port: the port for the server.
            username: the username to use for authentication
            password: the password for {username}
        """
        if None in [endpoint, method]:
            raise ValueError("endpoint or method missing")

        if endpoint.startswith("/"):
            endpoint = endpoint[1:]

        full_url = f"https://{host}:{port}/{endpoint}"

        request_kwargs = {
            "verify": CERT_PATH,
            "method": method.upper(),
            "url": full_url,
            "headers": {"Content-Type": "application/json", "Accept": "application/json"},
        }

        if isinstance(payload, str):
            request_kwargs["data"] = payload
        elif isinstance(payload, dict):
            request_kwargs["data"] = json.dumps(payload)
        try:
            with requests.Session() as s:
                s.auth = (username, password)
                resp = s.request(**request_kwargs)
                resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request {method} to {full_url} with payload: {payload} failed. \n{e}")
            raise OpenSearchHttpError(str(e))

        return resp.json()


class OpenSearchHttpError(Exception):
    """Exception thrown when an OpenSearch REST call fails."""


if __name__ == "__main__":
    main(ApplicationCharm)
