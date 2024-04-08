#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Collection of state objects for relations, apps and units."""
import logging
import socket
import subprocess
from typing import List, Literal, MutableMapping, Optional

from charms.data_platform_libs.v0.data_interfaces import Data
from literals import CHARM_USERS
from ops.model import Application, Relation, Unit
from typing_extensions import override

logger = logging.getLogger(__name__)

SUBSTRATES = Literal["vm", "k8s"]


class StateBase:
    """Base state object."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Unit | Application,
        substrate: SUBSTRATES,
    ):
        self.relation = relation
        self.data_interface = data_interface
        self.component = component
        self.substrate = substrate

    @property
    def relation_data(self) -> MutableMapping[str, str]:
        """The raw relation data."""
        if not self.relation or not self.data_interface:
            return {}

        my_data = {}
        if my_data_dict := self.data_interface.fetch_my_relation_data([self.relation.id]):
            my_data = my_data_dict.get(self.relation.id, {})

        try:
            other_data = self.data_interface.fetch_relation_data([self.relation.id])[
                self.relation.id
            ]
        except NotImplementedError:
            other_data = {}
        return my_data | other_data

    def update(self, items: dict[str, str]) -> None:
        """Writes to relation_data."""
        if not self.relation or not self.data_interface:
            return

        delete_fields = [key for key in items if not items[key]]
        update_fields = {k: items[k] for k in items if k not in delete_fields}
        if update_fields:
            self.data_interface.update_relation_data(self.relation.id, update_fields)
        if delete_fields:
            self.data_interface.delete_relation_data(self.relation.id, delete_fields)


class OpensearchServer(StateBase):
    """State collection metadata for a single related client application."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Application,
        substrate: SUBSTRATES,
        local_app: Application | None = None,
        password: str = "",
        endpoints: str = "",
        tls: bool = False,
    ):
        super().__init__(relation, data_interface, component, substrate)
        self.app = component
        self._password = password
        self._endpoints = endpoints
        self._tls = tls
        self._local_app = local_app

    @override
    def update(self, items: dict[str, str]) -> None:
        """Overridden update to allow for same interface, but writing to local app bag."""
        if not self.relation or not self._local_app:
            return

        self.data_interface.update_relation_data(self.relation.id, items)

    @property
    def username(self) -> Optional[str]:
        """The generated username for the client application."""
        # Until we settle user credential questions we statically return 'kibanaserver'
        # return self.relation_data.get("username")
        return "kibanaserver"

    @property
    def password(self) -> Optional[str]:
        """The generated password for the client application."""
        return self.relation_data.get("password")

    @property
    def endpoints(self) -> List[str]:
        """Connection endpoints for the client application to connect with."""
        endpoints_str = self.relation_data.get("endpoints")
        return endpoints_str.split(",") if endpoints_str else []

    @property
    def tls(self) -> bool:
        """Flag to confirm whether or not is TLS enabled.

        Returns:
            String of either 'enabled' or 'disabled'
        """
        return self._tls

    @property
    def tls_ca(self) -> Optional[str]:
        """The CA cert in case TLS is enabled.

        Returns:
            String of either 'enabled' or 'disabled'
        """
        return self.relation_data.get("tls-ca")


class ODCluster(StateBase):
    """State collection metadata for the charm application."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Application,
        substrate: SUBSTRATES,
    ):
        super().__init__(relation, data_interface, component, substrate)
        self.app = component

    @property
    def internal_user_credentials(self) -> dict[str, str]:
        """The passwords for the internal quorum and super users.

        Returns:
            Dict of key username, value password
        """
        return {
            user: password
            for user in CHARM_USERS
            if (password := self.relation_data.get(f"{user}-password"))
        }

    # -- TLS --

    @property
    def tls(self) -> bool:
        """Flag to check if TLS is enabled for the cluster."""
        return bool(self.relation_data.get("tls", ""))


class ODServer(StateBase):
    """State collection metadata for a charm unit."""

    def __init__(
        self,
        relation: Relation | None,
        data_interface: Data,
        component: Unit,
        substrate: SUBSTRATES,
    ):
        super().__init__(relation, data_interface, component, substrate)
        self.unit = component

    @property
    def unit_id(self) -> int:
        """The id of the unit from the unit name.

        e.g opensearch-dashboards/2 --> 2
        """
        return int(self.component.name.split("/")[1])

    # -- Cluster Init --

    @property
    def started(self) -> bool:
        """Flag to check if the unit has started the service."""
        return self.relation_data.get("state", None) == "started"

    @property
    def password_rotated(self) -> bool:
        """Flag to check if the unit has rotated their internal passwords."""
        return bool(self.relation_data.get("password-rotated", None))

    @property
    def hostname(self) -> str:
        """The hostname for the unit."""
        return socket.gethostname()

    @property
    def fqdn(self) -> str:
        """The Fully Qualified Domain Name for the unit."""
        return socket.getfqdn()

    @property
    def private_ip(self) -> str:
        """The IP for the unit."""
        return socket.gethostbyname(self.hostname)

    @property
    def public_ip(self) -> str:
        result = subprocess.check_output(
            [
                "bash",
                "-c",
                "ip a | grep global | grep -v 'inet 10.' | cut -d' ' -f6 | cut -d'/' -f1",
            ],
            text=True,
        )
        return result.rstrip()

    @property
    def host(self) -> str:
        """The hostname for the unit."""
        host = ""
        if self.substrate == "vm":
            for key in ["hostname", "ip", "private-address"]:
                if host := self.relation_data.get(key, ""):
                    break

        if self.substrate == "k8s":
            host = f"{self.component.name.split('/')[0]}-{self.unit_id}.{self.component.name.split('/')[0]}-endpoints"

        return host

    # -- TLS --

    @property
    def private_key(self) -> str:
        """The private-key contents for the unit to use for TLS."""
        return self.relation_data.get("private-key", "")

    # @property
    # def keystore_password(self) -> str:
    #     """The Java Keystore password for the unit to use for TLS."""
    #     return self.relation_data.get("keystore-password", "")
    #
    # @property
    # def truststore_password(self) -> str:
    #     """The Java Truststore password for the unit to use for TLS."""
    #     return self.relation_data.get("truststore-password", "")

    @property
    def csr(self) -> str:
        """The current certificate signing request contents for the unit."""
        return self.relation_data.get("csr", "")

    @property
    def certificate(self) -> str:
        """The certificate contents for the unit to use for TLS."""
        return self.relation_data.get("certificate", "")

    @property
    def ca(self) -> str:
        """The root CA contents for the unit to use for TLS."""
        return self.relation_data.get("ca-cert", "")

    @property
    def sans(self) -> dict[str, list[str]]:
        """The Subject Alternative Name for the unit's TLS certificates."""
        if not all([self.private_ip, self.hostname, self.fqdn]):
            return {}

        return {
            "sans_ip": [self.private_ip],
            "sans_dns": [self.hostname, self.fqdn],
        }
