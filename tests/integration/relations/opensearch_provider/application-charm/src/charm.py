#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Application charm that connects to database charms.

This charm is meant to be used only for testing of the libraries in this repository.
"""

import json
import logging
import socket
from typing import Dict, List, Optional, Union

import requests
from charms.data_platform_libs.v0.data_interfaces import (
    DatabaseCreatedEvent,
    DatabaseEndpointsChangedEvent,
    DatabaseRequires,
)
from ops.charm import ActionEvent, CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)


class ApplicationCharm(CharmBase):
    """Application charm that connects to database charms.

    TODO Dies if relation is incorrectly configured
    TODO document what that means, and link to it here.
    """

    def __init__(self, *args):
        super().__init__(*args)

        # Default charm events.
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.update_status, self._on_update_status)

        # Events related to the first database that is requested
        # (these events are defined in the database requires charm library).
        database_name = f'{self.app.name.replace("-", "_")}_first_database'

        permissive_roles = json.dumps({"roles": ["all_access"]})
        self.first_database = DatabaseRequires(
            self, "first-database", database_name, permissive_roles
        )
        self.framework.observe(
            self.first_database.on.database_created, self._on_first_database_created
        )
        self.framework.observe(
            self.first_database.on.endpoints_changed, self._on_first_database_endpoints_changed
        )

        # Events related to the second database that is requested
        # (these events are defined in the database requires charm library).
        database_name = f'{self.app.name.replace("-", "_")}_second_database'
        restrictive_roles = "{}"
        self.second_database = DatabaseRequires(
            self, "second-database", database_name, restrictive_roles
        )
        self.framework.observe(
            self.second_database.on.database_created, self._on_second_database_created
        )
        self.framework.observe(
            self.second_database.on.endpoints_changed, self._on_second_database_endpoints_changed
        )

        self.framework.observe(self.on.run_query_action, self._on_run_query_action)

    def _on_start(self, _) -> None:
        """Only sets an Active status."""
        self.unit.status = ActiveStatus()

    def _on_update_status(self, _) -> None:
        """Health check for database connection.

        If backend relation exists and is usable, set status to active.
        """
        if self.connection_check():
            self.unit.status = ActiveStatus()
        else:
            self.unit.status = BlockedStatus("No connection to opensearch charm")

    def connection_check(self) -> bool:
        """Simple connection check to see if backend exists and we can connect to it."""
        relations = self.model.relations.get("first-database", []) + self.model.relations.get(
            "second-database", []
        )
        if len(relations) == 0:
            return False
        for relation in relations:
            if not self.smoke_check(relation.id):
                return False
        return True

    def smoke_check(self, relation_id) -> bool:
        try:
            self.relation_request(relation_id, "GET", "/_nodes")
            # TODO check status
            return True
        except (OpenSearchHttpError, Exception) as e:
            logger.exception(e)
            return False

    # First database events observers.
    def _on_first_database_created(self, event: DatabaseCreatedEvent) -> None:
        """Event triggered when a database was created for this application."""
        # Retrieve the credentials using the charm library.
        logger.info(f"first database credentials: {event.username} {event.password}")
        self.unit.status = ActiveStatus("received database credentials of the first database")

    def _on_first_database_endpoints_changed(self, event: DatabaseEndpointsChangedEvent) -> None:
        """Event triggered when the read/write endpoints of the database change."""
        logger.info(f"first database endpoints have been changed to: {event.endpoints}")

    # Second database events observers.
    def _on_second_database_created(self, event: DatabaseCreatedEvent) -> None:
        """Event triggered when a database was created for this application."""
        # Retrieve the credentials using the charm library.
        logger.info(f"second database credentials: {event.username} {event.password}")
        self.unit.status = ActiveStatus("received database credentials of the second database")

    def _on_second_database_endpoints_changed(self, event: DatabaseEndpointsChangedEvent) -> None:
        """Event triggered when the read/write endpoints of the database change."""
        logger.info(f"second database endpoints have been changed to: {event.endpoints}")

    def _on_run_query_action(self, event: ActionEvent):
        """Runs queries."""
        raise NotImplementedError

    def relation_request(
        self,
        relation_id: int,
        method: str,
        endpoint: str,
        payload: Optional[Dict[str, any]] = None,
    ) -> Union[Dict[str, any], List[any]]:
        """Make an HTTP request to a specific relation."""
        databag = self.first_database.fetch_relation_data()[relation_id]
        username = databag.get("username")
        password = databag.get("password")
        endpoints = databag.get("endpoints").split(",")
        port = endpoints[0].split(":")[1]
        return self.request(
            method, endpoint, port, username, password, payload=payload, hosts=endpoints
        )

    def request(
        self,
        method: str,
        endpoint: str,
        port: int,
        username: str,
        password: str,
        payload: Optional[Dict[str, any]] = None,
        hosts: Optional[List[str]] = None,
    ) -> Union[Dict[str, any], List[any]]:
        """Make an HTTP request.

        Args:
            method: matching the known http methods.
            endpoint: relative to the base uri.
            payload: JSON / map body payload.
            hosts: host of the nodes we wish to make a request on.
            port: the port for the server.
            username: the username to use for authentication
            password: the password for {username}
        """
        if None in [endpoint, method]:
            raise ValueError("endpoint or method missing")

        if endpoint.startswith("/"):
            endpoint = endpoint[1:]

        target_host: Optional[str] = None
        for host_candidate in hosts:
            if is_reachable(host_candidate, port):
                target_host = host_candidate
                break

        if not target_host:
            logger.error("Hosts not reachable.")
            raise OpenSearchHttpError()

        full_url = f"https://{target_host}:{port}/{endpoint}"
        try:
            with requests.Session() as s:
                s.auth = (username, password)

                resp = s.request(
                    method=method.upper(),
                    url=full_url,
                    data=json.dumps(payload),
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                )

                resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request {method} to {full_url} with payload: {payload} failed. \n{e}")
            raise OpenSearchHttpError()

        return resp.json()


class OpenSearchHttpError(Exception):
    """Exception thrown when an OpenSearch REST call fails."""


def is_reachable(host: str, port: int) -> bool:
    """Attempting a socket connection to a host/port."""
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((host, port))
        return True
    except Exception as e:
        logger.error(e)
        return False
    finally:
        s.close()


if __name__ == "__main__":
    main(ApplicationCharm)
