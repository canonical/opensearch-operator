#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Resolve charm revisions for the upgrade-guide end-to-end test.

``REV_TO`` is resolved dynamically from the Charmhub channel map (latest
revision released on the 2/stable channel).

The Charmhub API does NOT expose workload (OpenSearch) versions — the
``version`` field on a channel-map entry is just the charm revision number —
so the rollback pairs cannot be derived dynamically. They come from a small
curated map (``REVISION_WORKLOAD_MAP``) maintained in this file:

  * ``REV_FROM_SAME``  — highest known revision with the SAME workload
                         version as ``REV_TO`` (same-workload rollback)
  * ``REV_FROM_DIFF``  — highest known revision with an OLDER workload
                         version (different-workload rollback)

When the curated map cannot satisfy a pair, ``PINNED_FALLBACK`` is used and a
loud warning is printed so the map gets refreshed (the monthly workflow run
is a good reminder).

Usage
-----
    python3 resolve_revisions.py            # print export lines
    python3 resolve_revisions.py -o env.sh  # write shell env file
"""

import json
import sys
import urllib.request
from pathlib import Path

CHARM_NAME = "opensearch"
CHANNEL = "2/stable"
API_URL = (
    "https://api.charmhub.io/v2/charms/info/"
    f"{CHARM_NAME}?fields=channel-map"
)

# Curated revision → workload (OpenSearch) version map.
# Refresh when the charm releases new revisions; keep at least one revision
# sharing the workload version of the current 2/stable release and one with
# an older workload version.
REVISION_WORKLOAD_MAP: dict[int, str] = {
    160: "2.17.0",
    167: "2.19.0",
    168: "2.19.1",
    344: "2.19.1",
    345: "2.19.1",
}

# Fallback ONLY — used when neither the API nor the curated map can produce
# a full set. Keep the workload version relationships intact when refreshing:
#   REV_FROM_DIFF < REV_FROM_SAME (same workload as REV_TO) < REV_TO
PINNED_FALLBACK = {
    "REV_TO": "168",
    "REV_FROM_SAME": "167",
    "REV_FROM_DIFF": "160",
}


def _version_key(version: str) -> tuple[int, ...]:
    """Turn '2.19.1' into (2, 19, 1) for comparison."""
    try:
        return tuple(int(p) for p in version.split("."))
    except ValueError:
        return ()


def fetch_latest_stable_revision() -> int | None:
    """Return the latest revision released on the target channel (amd64)."""
    request = urllib.request.Request(API_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)

    latest: int | None = None
    for entry in data.get("channel-map", []):
        channel = entry.get("channel", {})
        if channel.get("name") != CHANNEL or channel.get("risk") != "stable":
            continue
        if channel.get("base", {}).get("architecture") != "amd64":
            continue
        rev = entry.get("revision", {}).get("revision")
        if rev is not None and (latest is None or int(rev) > latest):
            latest = int(rev)
    return latest


def resolve() -> dict[str, str] | None:
    """Pick the three revisions.

    Returns None when a full set cannot be produced; the caller then falls
    back to the pinned values.
    """
    rev_to = fetch_latest_stable_revision()
    if rev_to is None:
        return None

    version_to = REVISION_WORKLOAD_MAP.get(rev_to)
    if version_to is None:
        # The curated map doesn't know this revision yet.
        return None

    rev_from_same: int | None = None
    rev_from_diff: int | None = None
    for rev, version in REVISION_WORKLOAD_MAP.items():
        if rev >= rev_to:
            continue
        if version == version_to and (rev_from_same is None or rev > rev_from_same):
            rev_from_same = rev
        if _version_key(version) < _version_key(version_to) and (
            rev_from_diff is None or rev > rev_from_diff
        ):
            rev_from_diff = rev

    if rev_from_same is None or rev_from_diff is None:
        return None

    return {
        "REV_TO": str(rev_to),
        "REV_FROM_SAME": str(rev_from_same),
        "REV_FROM_DIFF": str(rev_from_diff),
    }


def main() -> None:
    args = sys.argv[1:]
    output_path: Path | None = None
    if len(args) == 2 and args[0] == "-o":
        output_path = Path(args[1])
    elif args:
        print(__doc__)
        sys.exit(1)

    revisions: dict[str, str] | None = None
    try:
        revisions = resolve()
    except Exception as exc:  # noqa: BLE001 — network errors fall back
        print(f"Warning: revision resolution failed: {exc}", file=sys.stderr)

    if revisions is None:
        print(
            "WARNING: falling back to PINNED revisions — refresh "
            "REVISION_WORKLOAD_MAP / PINNED_FALLBACK in resolve_revisions.py!",
            file=sys.stderr,
        )
        revisions = dict(PINNED_FALLBACK)

    lines = [f'export {key}="{value}"' for key, value in sorted(revisions.items())]
    content = "\n".join(lines) + "\n"

    if output_path:
        output_path.write_text(content, encoding="utf-8")
        print(f"Written revision exports → {output_path}")
    print(content, end="")


if __name__ == "__main__":
    main()
