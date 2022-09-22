from typing import List

from ops.charm import CharmBase


def get_host_ip(charm: CharmBase, peer_relation_name: str) -> str:
    address = charm\
        .model \
        .get_binding(peer_relation_name) \
        .network \
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
