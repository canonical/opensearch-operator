#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
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

        # Events related to the first database that is requested (these events are defined in the
        # database requires charm library).
        # Albums index is used in integration test
        self.first_opensearch = OpenSearchRequires(self, "first-index", "albums", "")

        self.framework.observe(
            self.first_opensearch.on.index_created, self._on_authentication_updated
        )
        self.framework.observe(  # TODO check if I can delete this
            self.first_opensearch.on.authentication_updated, self._on_authentication_updated
        )

        # Events related to the second index that is requested
        # (these events are defined in the database requires charm library).
        index_name = f'{self.app.name.replace("-", "_")}_second_opensearch'
        self.second_opensearch = OpenSearchRequires(self, "second-index", index_name, "")
        self.framework.observe(
            self.second_opensearch.on.index_created, self._on_authentication_updated
        )
        self.framework.observe(  # TODO check if I can delete this
            self.second_opensearch.on.authentication_updated, self._on_authentication_updated
        )

        self.admin_opensearch = OpenSearchRequires(self, "admin", "admin-index", "admin")
        self.framework.observe(
            self.admin_opensearch.on.index_created, self._on_authentication_updated
        )
        self.framework.observe(  # TODO check if I can delete this
            self.admin_opensearch.on.authentication_updated, self._on_authentication_updated
        )

        self.framework.observe(self.on.run_request_action, self._on_run_request_action)

        self.relations = {
            "first-index": self.first_opensearch,
            "second-index": self.second_opensearch,
            "admin": self.admin_opensearch,
        }

    def _on_update_status(self, _) -> None:
        """Health check for index connection."""
        if self.connection_check():
            self.unit.status = ActiveStatus()
        else:
            logger.error("connection check to opensearch charm failed")
            self.unit.status = BlockedStatus("No connection to opensearch charm")

    def connection_check(self) -> bool:
        """Simple connection check to see if backend exists and we can connect to it."""
        relations = self.model.relations.get("first-index", []) + self.model.relations.get(
            "second-index", []
        )
        if not relations:
            return False

        connected = True
        for relation in relations:
            try:
                self.relation_request(relation.name, relation.id, "GET", "/")
            except OpenSearchHttpError as e:
                logger.error(e)
                logger.error(f"relation {relation} didn't connect")
                connected = False

        return connected

    def _on_authentication_updated(self, event: AuthenticationEvent):
        if event.tls != "True":
            return

        tls_ca = event.tls_ca
        if not tls_ca:
            tls_ca = self.first_opensearch.fetch_relation_data()[event.relation.id].get(
                "tls_ca", None
            )
            if not tls_ca:
                event.defer()  # We're waiting until we get a CA.
        logger.error(f"writing cert to {CERT_PATH}.")
        with open(CERT_PATH, "w") as f:
            f.write(tls_ca)

    # ==============
    #  Action hooks
    # ==============

    def _on_run_request_action(self, event: ActionEvent):
        logger.info(event.params)
        relation = self.relations[event.params["relation-name"]]
        relation_id = event.params["relation-id"]
        databag = relation.fetch_relation_data()[relation_id]
        method = event.params["method"]
        endpoint = event.params["endpoint"]
        payload = event.params.get("payload", None)
        if payload:
            payload = payload.replace("\\", "")

        username = databag.get("username")
        password = databag.get("password")
        host = databag.get("endpoints").split(",")[0]
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
        relation = self.relations[relation_name]
        databag = relation.fetch_relation_data()[relation_id]
        username = databag.get("username")
        password = databag.get("password")
        hosts = databag.get("endpoints", "").split(",")

        if None in [username, password] or not hosts:
            raise OpenSearchHttpError

        host, port = hosts[0].split(":")

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
