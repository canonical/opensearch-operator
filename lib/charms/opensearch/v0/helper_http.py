from typing import List, Optional, Dict, Any

from tenacity import RetryCallState

from charms.opensearch.v0.helper_networking import reachable_hosts


# The unique Charmhub library identifier, never change it
LIBID = "f8bb15ca9ffc4e3f8d113421e03abe06"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


def error_http_retry_log(
    logger, retry_max: int, method: str, url: str, payload: Optional[Dict[str, Any]]
):
    def log_error(retry_state: RetryCallState):
        logger.error(
            f"Request {method} to {url} with payload: {payload} failed."
            f"(Attempts left: {retry_max - retry_state.attempt_number})\n"
            f"\tError: {retry_state.outcome.exception()}"
        )
    return log_error


def full_urls(
    primary_host: str,
    port: int,
    path: str,
    alt_hosts: List[str],
    check_hosts_reach: bool = False
) -> List[str]:
    """Returns a list of well formatted and potentially reachable hosts."""
    target_hosts = [primary_host]
    if alt_hosts:
        target_hosts.extend(
            [alt_host for alt_host in alt_hosts if alt_host != primary_host]
        )

    if not check_hosts_reach:
        return target_hosts

    return [
        f"https://{host_candidate}:{port}/{path}"
        for host_candidate in reachable_hosts(target_hosts)
    ]
