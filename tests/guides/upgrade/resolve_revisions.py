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
# Preferred deploy base (see bootstrap.sh). Revisions on other bases cannot
# be refreshed to ("cannot upgrade from single base" error in Juju), so the
# resolver first tries to find a full revision set on this base. When the
# channel map has no valid upgrade pair on the preferred base (e.g. only one
# revision per base is released), it falls back to the alternate base and
# reports the chosen base so the bootstrap can deploy on it.
PREFERRED_BASE = "ubuntu@24.04"
FALLBACK_BASE = "ubuntu@22.04"
API_URL = (
    "https://api.charmhub.io/v2/charms/info/"
    f"{CHARM_NAME}?fields=channel-map"
)

# Curated revision → (workload OpenSearch version, base) map.
# Sources: docs/reference/release-notes/ (rev 168 → 2.17.0, rev 315 → 2.19.4)
# and the Charmhub channel map. Refresh when the charm releases new
# revisions; keep at least one revision sharing the workload version of the
# current 2/stable release and one with an older workload version — both on
# the same base as the current release.
REVISION_WORKLOAD_MAP: dict[int, tuple[str, str]] = {
    168: ("2.17.0", "ubuntu@22.04"),  # Sept 2024
    315: ("2.19.4", "ubuntu@24.04"),  # Dec 2025, first 24.04 release
    344: ("2.19.4", "ubuntu@24.04"),  # Apr 2026
    345: ("2.19.4", "ubuntu@22.04"),  # Apr 2026
}

# Fallback ONLY — used when neither the API nor the curated map can produce
# a full set. Keep the workload version relationships intact when refreshing:
#   REV_FROM_DIFF < REV_FROM_SAME (same workload as REV_TO) < REV_TO
# All three must share the same base.
PINNED_FALLBACK = {
    "REV_TO": "344",
    "REV_FROM_SAME": "315",
    "REV_FROM_DIFF": "315",  # no older-workload 24.04 revision known; same as FROM_SAME
    "DEPLOY_BASE": "ubuntu@24.04",
}


def _version_key(version: str) -> tuple[int, ...]:
    """Turn '2.19.1' into (2, 19, 1) for comparison."""
    try:
        return tuple(int(p) for p in version.split("."))
    except ValueError:
        return ()


def fetch_channel_map() -> list[dict]:
    """Return all channel-map entries for the charm (amd64, any base)."""
    request = urllib.request.Request(API_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    return [
        e
        for e in data.get("channel-map", [])
        if e.get("channel", {}).get("base", {}).get("architecture") == "amd64"
    ]


def _entry_base(entry: dict) -> str:
    base = entry.get("channel", {}).get("base", {})
    return f"{base.get('name')}@{base.get('channel')}"


def fetch_latest_stable_revision(channel_map: list[dict], base: str) -> int | None:
    """Return the latest revision released on the target channel and *base*."""
    latest: int | None = None
    for entry in channel_map:
        channel = entry.get("channel", {})
        if channel.get("name") != CHANNEL or channel.get("risk") != "stable":
            continue
        if _entry_base(entry) != base:
            continue
        rev = entry.get("revision", {}).get("revision")
        if rev is not None and (latest is None or int(rev) > latest):
            latest = int(rev)
    return latest


def resolve() -> dict[str, str] | None:
    """Pick the three revisions plus the deploy base.

    Tries the preferred base first; when the channel map has no valid
    revision set on it, falls back to the alternate base. Returns None when
    neither base yields a full set; the caller then falls back to the pinned
    values.
    """
    channel_map = fetch_channel_map()

    for base in (PREFERRED_BASE, FALLBACK_BASE):
        rev_to = fetch_latest_stable_revision(channel_map, base)
        if rev_to is None:
            continue

        entry = REVISION_WORKLOAD_MAP.get(rev_to)
        if entry is None:
            # The curated map doesn't know this revision yet.
            continue
        version_to, base_to = entry
        if base_to != base:
            continue

        rev_from_same: int | None = None
        rev_from_diff: int | None = None
        for rev, (version, rev_base) in REVISION_WORKLOAD_MAP.items():
            if rev >= rev_to or rev_base != base:
                continue
            if version == version_to and (rev_from_same is None or rev > rev_from_same):
                rev_from_same = rev
            if _version_key(version) < _version_key(version_to) and (
                rev_from_diff is None or rev > rev_from_diff
            ):
                rev_from_diff = rev

        if rev_from_same is None:
            continue
        # When no older-workload revision exists on this base, reuse the
        # same-workload revision: the different-workload scenario then
        # degrades gracefully (documented in README).
        if rev_from_diff is None:
            rev_from_diff = rev_from_same

        return {
            "REV_TO": str(rev_to),
            "REV_FROM_SAME": str(rev_from_same),
            "REV_FROM_DIFF": str(rev_from_diff),
            "DEPLOY_BASE": base,
        }
    return None


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
