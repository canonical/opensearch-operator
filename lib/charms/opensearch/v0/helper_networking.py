# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for networking related operations."""
import logging
import os
import socket
import subprocess
from typing import Dict, List, Optional

from ops.charm import CharmBase
from ops.model import Unit

# The unique Charmhub library identifier, never change it
LIBID = "afaa4474be1f4ae09089631dbe729d4c"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)


def get_host_ip(charm: CharmBase, peer_relation_name: str) -> str:
    """Fetches the IP address of the current unit."""
    address = charm.model.get_binding(peer_relation_name).network.bind_address
    return str(address)


def get_host_public_ip() -> Optional[str]:
    """Fetches the Public IP address of the current unit."""
    cmd = "dig +short myip.opendns.com @resolver1.opendns.com"
    output = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        text=True,
        encoding="utf-8",
        timeout=25,
        env=os.environ,
    )
    if output.returncode != 0:
        return None

    return output.stdout.strip()


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

    # Sometimes the above command doesn't get the current node, so ensure we get this unit's ip.
    unit_ip_map[charm.unit.name.split("/")[1]] = get_host_ip(charm, peer_relation_name)

    return unit_ip_map


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


def reachable_hosts(hosts: List[str]) -> List[str]:
    """Returns a list of reachable hosts."""
    reachable: List[str] = []
    for host_candidate in hosts:
        if is_reachable(host_candidate, 9200):
            reachable.append(host_candidate)

    return reachable
