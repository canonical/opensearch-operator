#!/bin/bash
# Shared helpers for tutorial spread tests.
#
# Source this file at the top of every generated script (done automatically
# by extract_commands.py):
#   . "$SPREAD_PATH/helpers.sh"
#
# NOTE: The functions below (wait_idle, retry_until_success) are designed for
# Juju-based Charmed Operator tutorials. If your tutorial does not use Juju,
# replace or extend this file with your own helpers.

# Spread SSHs in as root but does not always set HOME=/root, which causes the
# Juju client to fail looking up its config in $HOME/.local/share/juju.
export HOME=/root

# ---------------------------------------------------------------------------
# wait_idle – poll until every Juju unit in the model is active/idle.
#
# Usage:
#   wait_idle [--timeout SECONDS] [--interval SECONDS]
#             [--allow-blocked APP1,APP2,...]
#
# Defaults:
#   --timeout  600   (10 minutes)
#   --interval  30   (check every 30 seconds)
#
# --allow-blocked accepts a comma-separated list of application names that
# are expected to be in blocked/idle state (e.g. data-integrator without a
# relation).  Units belonging to those apps are treated as settled when they
# are blocked/idle.  All other units must still be active/idle.
#
# Progress output (one line per poll interval):
#   "still provisioning"            – juju status returned no units yet
#   "N unit(s) not yet active/idle" – units exist but are still settling
#   "All units active/idle"         – success, final juju status is printed
#   "Timed out after Xs"            – timeout reached, final juju status is printed
#
# Returns 0 when all units are active/idle, 1 on timeout.
# ---------------------------------------------------------------------------
wait_idle() {
    local timeout=600
    local interval=30
    local allow_blocked=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout)       timeout="$2";       shift 2 ;;
            --interval)      interval="$2";      shift 2 ;;
            --allow-blocked) allow_blocked="$2"; shift 2 ;;
            *) echo "wait_idle: unknown option: $1" >&2; return 1 ;;
        esac
    done

    local elapsed=0
    echo "Waiting for all Juju units to be active/idle (timeout=${timeout}s, poll=${interval}s)…"

    while [[ "$elapsed" -lt "$timeout" ]]; do
        local not_ready
        # Run the poll pipeline with pipefail disabled so a non-zero exit from
        # "juju status" (common while machines are still provisioning) does not
        # abort a calling script that has  set -euo pipefail  active.
        not_ready=$(
            set +o pipefail
            export ALLOW_BLOCKED="$allow_blocked"
            juju status --format=json 2>/dev/null | python3 -c '
import json, sys, os
try:
    data = json.load(sys.stdin)
    allowed = set(os.environ.get("ALLOW_BLOCKED", "").split(",")) - {""}
    not_ready = 0
    total_units = 0
    for app_name, app in data.get("applications", {}).items():
        for unit in app.get("units", {}).values():
            total_units += 1
            ws = unit.get("workload-status", {}).get("current", "")
            js = unit.get("juju-status",    {}).get("current", "")
            if ws == "active" and js == "idle":
                continue
            if ws == "blocked" and js == "idle" and app_name in allowed:
                continue
            not_ready += 1
    if total_units == 0:
        print("provisioning")
    else:
        print(not_ready)
except Exception:
    print("provisioning")
'
        ) || not_ready="provisioning"

        if [[ "$not_ready" == "0" ]]; then
            echo "All units active/idle after ${elapsed}s."
            juju status
            return 0
        elif [[ "$not_ready" == "provisioning" ]]; then
            echo "[${elapsed}s elapsed] still provisioning – rechecking in ${interval}s…"
        else
            echo "[${elapsed}s elapsed] ${not_ready} unit(s) not yet active/idle – rechecking in ${interval}s…"
        fi
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    echo "Timed out after ${timeout}s. Final status:"
    juju status
    return 1
}

# ---------------------------------------------------------------------------
# retry_until_success – retry a command with a fixed interval until it
# succeeds or the timeout is reached.
#
# Usage:
#   retry_until_success [--timeout SECONDS] [--interval SECONDS]
#                       [--description TEXT] -- COMMAND [ARGS...]
#
# Defaults:
#   --timeout   1200  (20 minutes)
#   --interval   120  (retry every 2 minutes)
#
# Everything after the ``--`` separator is executed as a command on each
# attempt.  If the command exits 0, the function returns 0 immediately.
# If all attempts are exhausted, returns 1.
# ---------------------------------------------------------------------------
retry_until_success() {
    local timeout=1200
    local interval=120
    local description="command"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout)     timeout="$2";     shift 2 ;;
            --interval)    interval="$2";    shift 2 ;;
            --description) description="$2"; shift 2 ;;
            --)            shift; break ;;
            *) echo "retry_until_success: unknown option: $1" >&2; return 1 ;;
        esac
    done

    if [[ $# -eq 0 ]]; then
        echo "retry_until_success: no command specified after --" >&2
        return 1
    fi

    local elapsed=0
    echo "Retrying ${description} (timeout=${timeout}s, interval=${interval}s)…"

    while [[ "$elapsed" -lt "$timeout" ]]; do
        if "$@" 2>&1; then
            echo "${description} succeeded after ${elapsed}s."
            return 0
        fi
        echo "[${elapsed}s elapsed] ${description} failed – retrying in ${interval}s…"
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    echo "ERROR: ${description} did not succeed within ${timeout}s"
    return 1
}
