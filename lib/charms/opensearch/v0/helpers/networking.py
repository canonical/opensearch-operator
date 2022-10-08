# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for networking related operations."""
import socket
from typing import Dict

from ops.charm import CharmBase
from ops.model import Unit

# The unique Charmhub library identifier, never change it
LIBID = "f4bd9c1dad554f9ea52954b8181cdc19"
LIBAPI = 0
LIBPATCH = 0


def get_host_ip(charm: CharmBase, peer_relation_name: str) -> str:
    """Fetches the IP address of the current unit."""
    address = charm.model.get_binding(peer_relation_name).network.bind_address
    return str(address)


def get_hostname_by_unit(charm: CharmBase, unit_name: str) -> str:
    """Create a DNS name for an OpenSearch unit."""
    unit_id = unit_name.split("/")[1]
    return f"{charm.app.name}-{unit_id}.{charm.app.name}-endpoints"


def unit_ip(charm: CharmBase, unit: Unit, peer_relation_name: str) -> str:
    """Returns the ip address of a given unit."""
    # check if host is current host
    if unit == charm.unit:
        return get_host_ip(charm, peer_relation_name)

    private_address = (
        charm.model.get_relation(peer_relation_name).data[unit].get("private-address")
    )
    return str(private_address)


def units_ips(charm: CharmBase, peer_relation_name: str) -> Dict[str, str]:
    """Returns the mapping "unit id / ip address" of all units."""
    unit_ip_map = {}
    for unit in charm.model.get_relation(peer_relation_name).units:
        unit_id = unit.name.split("/")[1]
        unit_ip_map[unit_id] = unit_ip(charm, unit, peer_relation_name)

    return unit_ip_map


def is_reachable(ip_address: str, port: int) -> bool:
    """Attempting a socket connection to a host/port"""
    s = socket.socket()
    try:
        s.connect((ip_address, port))
        return True
    except:
        return False
    finally:
        s.close()
