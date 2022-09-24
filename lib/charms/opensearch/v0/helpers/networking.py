from typing import List, Dict

from ops.charm import CharmBase
from ops.model import Unit


def get_host_ip(charm: CharmBase, peer_relation_name: str) -> str:
    address = charm\
        .model\
        .get_binding(peer_relation_name)\
        .network\
        .bind_address

    return str(address)


def get_hostname_by_unit(charm: CharmBase, unit_name: str) -> str:
    """Create a DNS name for an OpenSearch unit.
    Args:
        charm: the caller charm
        unit_name: the juju unit name, e.g. "opensearch/1".
    Returns:
        A string representing the hostname of the OpenSearch unit.
    """
    unit_id = unit_name.split("/")[1]
    return f"{charm.app.name}-{unit_id}.{charm.app.name}-endpoints"


def unit_ip(charm: CharmBase, unit: Unit, peer_relation_name: str) -> str:
    """Returns the ip address of a given unit."""
    # check if host is current host
    if unit == charm.unit:
        return get_host_ip(charm, peer_relation_name)

    private_address = charm\
        .model\
        .get_relation(peer_relation_name)\
        .data[unit]\
        .get("private-address")

    return str(private_address)


def units_ips(charm: CharmBase, peer_relation_name: str) -> Dict[str, str]:
    """Returns the mapping "unit id / ip address" of all units."""
    unit_ip_map = {}
    for unit in charm.model.get_relation(peer_relation_name).units:
        unit_id = unit.name.split("/")[1]
        unit_ip_map[unit_id] = unit_ip(charm, unit, peer_relation_name)

    return unit_ip_map
