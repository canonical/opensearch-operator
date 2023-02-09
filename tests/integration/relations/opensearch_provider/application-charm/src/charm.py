#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Application charm that connects to opensearch using the opensearch-client relation."""

import json
import logging
from typing import Dict, List, Optional, Union

import requests
from charms.data_platform_libs.v0.data_interfaces import (
    HostsChangedEvent,
    IndexCreatedEvent,
    OpenSearchRequires,
)
from ops.charm import ActionEvent, CharmBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)


class ApplicationCharm(CharmBase):
    """Application charm that connects to database charms.

    Enters BlockedStatus if it cannot constantly reach the database.
    """

    def __init__(self, *args):
        super().__init__(*args)

        # Default charm events.
        self.framework.observe(self.on.update_status, self._on_update_status)

        # Events related to the first database that is requested
        # (these events are defined in the database requires charm library).
        database_name = f'{self.app.name.replace("-", "_")}_first_opensearch'

        permissive_roles = json.dumps({"roles": ["all_access"]})
        self.first_opensearch = OpenSearchRequires(
            self, "first-database", database_name, permissive_roles
        )
        self.framework.observe(
            self.first_opensearch.on.index_created, self._on_first_opensearch_created
        )
        self.framework.observe(
            self.first_opensearch.on.hosts_changed, self._on_first_opensearch_hosts_changed
        )

        # Events related to the second database that is requested
        # (these events are defined in the database requires charm library).
        database_name = f'{self.app.name.replace("-", "_")}_second_opensearch'
        # TODO change this to include only permissions and action groups, and verify that we can
        # create roles when necessary.
        roles = {
            "roles": ["readall"],
            "permissions": ["TODO find some permissions", ""],
            "action_groups": ["TODO find some action groups", ""],
        }
        complex_roles = json.dumps(roles)
        self.second_opensearch = OpenSearchRequires(
            self, "second-database", database_name, complex_roles
        )
        self.framework.observe(
            self.second_opensearch.on.index_created, self._on_second_opensearch_created
        )
        self.framework.observe(
            self.second_opensearch.on.hosts_changed, self._on_second_opensearch_hosts_changed
        )

        self.framework.observe(self.on.run_query_action, self._on_run_query_action)

    def _on_update_status(self, _) -> None:
        """Health check for database connection."""
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
            resp = self.relation_request(relation_id, "GET", "/")
            logger.info(resp)
            return bool(resp)
        except (OpenSearchHttpError, Exception) as e:
            logger.error(e)
            return False

    # First database events observers.
    def _on_first_opensearch_created(self, event: IndexCreatedEvent) -> None:
        """Event triggered when a database was created for this application."""
        logging.info(f"first database credentials: {event.username} {event.password}")

    def _on_first_opensearch_hosts_changed(self, event: HostsChangedEvent) -> None:
        """Event triggered when the opensearch hosts change."""
        logger.info(f"first database endpoints have been changed to: {event.hosts}")

    # Second database events observers.
    def _on_second_opensearch_created(self, event: IndexCreatedEvent) -> None:
        """Event triggered when a database was created for this application."""
        logger.info(f"second database credentials: {event.username} {event.password}")

    def _on_second_opensearch_hosts_changed(self, event: HostsChangedEvent) -> None:
        """Event triggered when the opensearch hosts change."""
        logger.info(f"second database endpoints have been changed to: {event.hosts}")

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
        databag = self.first_opensearch.fetch_relation_data()[relation_id]
        logging.error(databag)
        username = databag.get("username")
        password = databag.get("password")
        hosts = databag.get("hosts", "").split(",")

        if None in [username, password] or len(hosts) == 0:
            raise OpenSearchHttpError

        host = hosts[0].split(":")[0]
        port = int(hosts[0].split(":")[1])

        return self.request(
            method,
            endpoint,
            port,
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

        # add username and password if auth continues to fail
        full_url = f"https://{host}:{port}/{endpoint}"
        try:
            with requests.Session() as s:
                s.auth = (username, password)
                request_kwargs = {
                    "verify": False,  # TODO this should be a cert once this relation has TLS.
                    "method": method.upper(),
                    "url": full_url,
                    "headers": {"Content-Type": "application/json"},
                }
                if payload is not None:
                    request_kwargs["data"] = json.dumps(payload)
                    request_kwargs["headers"]["Accept"] = "application/json"

                resp = s.request(**request_kwargs)

                resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request {method} to {full_url} with payload: {payload} failed. \n{e}")
            raise OpenSearchHttpError()

        return resp.json()


class OpenSearchHttpError(Exception):
    """Exception thrown when an OpenSearch REST call fails."""


if __name__ == "__main__":
    main(ApplicationCharm)
